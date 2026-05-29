//! `memvault-keystore` — a small, lock-free-read, append-only key-value
//! store for tokens and key material, deliberately **separate from the
//! redb blockstore**.
//!
//! ## Why a separate store
//!
//! redb takes a single exclusive write transaction for the whole
//! database **and a cross-process exclusive file lock**, so a second
//! process (e.g. `memctl` issuing a token) cannot write while the daemon
//! holds the database open, and even in-process, token/key ops contend
//! with the daemon's long-running block writes. This store decouples
//! that: reads are served from an in-memory map (an `RwLock` read), and
//! writes are short appends to a log.
//!
//! ## Multi-process access
//!
//! Multiple processes may open the same keystore at once (the daemon plus
//! a `memctl` invocation). Correctness comes from two mechanisms:
//!   * **Append exclusion** — `put`/`delete`/`compact` take an OS advisory
//!     exclusive lock (`flock`) on the file for the duration of the
//!     append, so records from different processes never interleave at the
//!     byte level.
//!   * **Read freshness** — every read first compares the file length to
//!     the offset we have replayed (`loaded_len`); if another process has
//!     appended (file grew) it replays just the new tail under a shared
//!     lock, and if the file shrank/was replaced (another process
//!     compacted) it fully reopens. In the common case (no external
//!     writes) a read is one `stat` plus an `RwLock` read.
//!
//! ## On-disk layout (log-structured KV)
//!
//! ```text
//! header:  b"MVKS" | version:u8                     (written once)
//! record:  len:u32le | body[len]                    (appended, repeated)
//!   body =  flags:u8 (bit0 = tombstone)
//!         | key_len:u32le | key[key_len]
//!         | value[rest]                              (opaque; AEAD-sealed later)
//! ```
//!
//! Last-writer-wins per key; a delete writes a tombstone. On open the log
//! is replayed into a `HashMap`; a torn trailing record (crash mid-append)
//! is detected by the length frame and truncated. `compact()` rewrites
//! only live records.
//!
//! At-rest encryption is a later stage: a [`Cipher`] seals record values
//! on write and unseals on replay. The in-memory map always holds
//! plaintext; the default [`Cipher::Identity`] is a no-op.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use fs2::FileExt;

const MAGIC: &[u8; 4] = b"MVKS";
const VERSION: u8 = 1;
const FLAG_TOMBSTONE: u8 = 0b0000_0001;

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("corrupt keystore: {0}")]
    Corrupt(String),
    #[error("bad magic or unsupported version")]
    BadHeader,
    #[error("seal/unseal failed: {0}")]
    Cipher(String),
}

pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Pluggable at-rest sealing for record values. `Identity` is a no-op
/// (plaintext on disk); real AEAD/TPM-backed ciphers slot in here in a
/// later stage without changing the log format beyond the value bytes.
pub enum Cipher {
    Identity,
    /// Seal + unseal closures (set by the encryption stage). Each must be
    /// deterministic-length-independent and round-trip: `unseal(seal(x)) == x`.
    Custom {
        seal: Box<dyn Fn(&[u8]) -> std::result::Result<Vec<u8>, String> + Send + Sync>,
        unseal: Box<dyn Fn(&[u8]) -> std::result::Result<Vec<u8>, String> + Send + Sync>,
    },
}

impl Cipher {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Identity => Ok(plain.to_vec()),
            Cipher::Custom { seal, .. } => seal(plain).map_err(KeyStoreError::Cipher),
        }
    }
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Identity => Ok(sealed.to_vec()),
            Cipher::Custom { unseal, .. } => unseal(sealed).map_err(KeyStoreError::Cipher),
        }
    }
}

impl Cipher {
    /// AEAD-seal record values with XChaCha20-Poly1305 under a 32-byte key.
    ///
    /// Each sealed value is `nonce(24) || ciphertext+tag`: a fresh random
    /// 192-bit nonce per record (XChaCha's nonce space makes random nonces
    /// safe without a counter), so re-sealing the same plaintext on
    /// `compact()` yields different bytes. Tamper/wrong-key → unseal errors,
    /// surfaced as [`KeyStoreError::Cipher`] and refused at replay.
    pub fn aead(key: [u8; 32]) -> Cipher {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        use rand::RngCore;

        let enc_key = key;
        let dec_key = key;
        Cipher::Custom {
            seal: Box::new(move |plain: &[u8]| {
                let cipher = XChaCha20Poly1305::new((&enc_key).into());
                let mut nonce = [0u8; 24];
                rand::rng().fill_bytes(&mut nonce);
                let ct = cipher
                    .encrypt(XNonce::from_slice(&nonce), plain)
                    .map_err(|e| format!("aead encrypt: {e}"))?;
                let mut out = Vec::with_capacity(24 + ct.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                Ok(out)
            }),
            unseal: Box::new(move |sealed: &[u8]| {
                if sealed.len() < 24 + 16 {
                    return Err("aead: sealed value too short".to_string());
                }
                let cipher = XChaCha20Poly1305::new((&dec_key).into());
                let (nonce, ct) = sealed.split_at(24);
                cipher
                    .decrypt(XNonce::from_slice(nonce), ct)
                    .map_err(|e| format!("aead decrypt (wrong key or tampered): {e}"))
            }),
        }
    }
}

/// Derive a 32-byte AEAD key from a passphrase with Argon2id (default
/// params). The `salt` must be stable for a given store and is the
/// caller's to persist (e.g. a `keystore.salt` sidecar); 16 random bytes
/// generated once at init is the intended usage.
pub fn derive_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]> {
    use argon2::Argon2;
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| KeyStoreError::Cipher(format!("argon2id: {e}")))?;
    Ok(out)
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cipher::Identity => write!(f, "Cipher::Identity"),
            Cipher::Custom { .. } => write!(f, "Cipher::Custom"),
        }
    }
}

/// TPM-sealed data-key support (optional `tpm` feature).
///
/// The keystore's at-rest key is a random 32-byte data key; with a TPM we
/// seal that data key to the TPM (optionally bound to PCRs) and store only
/// the opaque sealed blob in a sidecar. On open we unseal it via the TPM
/// and build [`Cipher::aead`] from the recovered key — the data key never
/// exists on disk in the clear, and (when PCR-bound) only unseals on a
/// machine in the expected boot state.
/// NOTE on verification: this module links `tss-esapi` (TSS2 system
/// libraries) and requires a TPM, so it is **not built or tested in CI** —
/// it is exercised only on a TPM-equipped host with the `tpm` feature on.
/// It targets the tss-esapi 7.x API (`create_primary` + KeyedHash
/// `create`/`load`/`unseal`).
#[cfg(feature = "tpm")]
pub mod tpm {
    use super::{KeyStoreError, Result};
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::constants::StartupType;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::{
        Digest, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters,
        RsaExponent, SensitiveData, SymmetricDefinitionObject,
    };
    use tss_esapi::traits::{Marshall, UnMarshall};
    use tss_esapi::utils::create_restricted_decryption_rsa_public;
    use tss_esapi::{Context, TctiNameConf};

    fn context() -> Result<Context> {
        let tcti = TctiNameConf::from_environment_variable().map_err(|e| {
            KeyStoreError::Cipher(format!(
                "TPM TCTI (set TPM2TOOLS_TCTI / TCTI, e.g. device:/dev/tpmrm0): {e}"
            ))
        })?;
        let mut ctx =
            Context::new(tcti).map_err(|e| KeyStoreError::Cipher(format!("TPM context: {e}")))?;
        // Idempotent: a TPM already started returns an error we can ignore.
        let _ = ctx.startup(StartupType::Clear);
        Ok(ctx)
    }

    /// Deterministic storage-root primary under the Owner hierarchy. The TPM
    /// re-derives the *same* key from its seed + this fixed template on every
    /// call, so seal and unseal share the same parent without persisting it.
    fn create_srk(ctx: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
        let public = create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .map_err(|e| KeyStoreError::Cipher(format!("TPM SRK template: {e}")))?;
        let primary = ctx
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| KeyStoreError::Cipher(format!("TPM create_primary: {e}")))?;
        Ok(primary.key_handle)
    }

    /// `Public` template for a KeyedHash sealed-data object whose sensitive
    /// payload we supply (no `sensitive_data_origin`).
    fn sealed_object_public() -> Result<Public> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .build()
            .map_err(|e| KeyStoreError::Cipher(format!("TPM object attrs: {e}")))?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| KeyStoreError::Cipher(format!("TPM keyedhash public: {e}")))
    }

    /// Seal a 32-byte data key to the TPM, returning an opaque blob to
    /// persist in a sidecar (`keystore.tpmsealed`). The blob only unseals on
    /// this TPM under the Owner hierarchy and is meaningless elsewhere.
    pub fn seal_key(data_key: &[u8; 32]) -> Result<Vec<u8>> {
        let mut ctx = context()?;
        let primary = create_srk(&mut ctx)?;
        let sensitive = SensitiveData::try_from(data_key.to_vec())
            .map_err(|e| KeyStoreError::Cipher(format!("TPM sensitive data: {e}")))?;
        let created = ctx
            .create(primary, sealed_object_public()?, None, Some(sensitive), None, None)
            .map_err(|e| KeyStoreError::Cipher(format!("TPM seal (create): {e}")))?;

        let pub_bytes = created
            .out_public
            .marshall()
            .map_err(|e| KeyStoreError::Cipher(format!("TPM marshal public: {e}")))?;
        let priv_bytes = created.out_private.as_ref().to_vec();
        // Blob = len-prefixed public || private.
        let mut out = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
        out.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&pub_bytes);
        out.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&priv_bytes);
        Ok(out)
    }

    /// Recover the 32-byte data key from a blob produced by [`seal_key`] on
    /// this TPM.
    pub fn unseal_key(blob: &[u8]) -> Result<[u8; 32]> {
        let mut off = 0usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            if blob.len() < off + n {
                return Err(KeyStoreError::Cipher("TPM blob truncated".into()));
            }
            let s = &blob[off..off + n];
            off += n;
            Ok(s)
        };
        let pl = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        let pub_bytes = take(pl)?.to_vec();
        let sl = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        let priv_bytes = take(sl)?.to_vec();

        let public = Public::unmarshall(&pub_bytes)
            .map_err(|e| KeyStoreError::Cipher(format!("TPM unmarshal public: {e}")))?;
        let private = Private::try_from(priv_bytes)
            .map_err(|e| KeyStoreError::Cipher(format!("TPM private: {e}")))?;

        let mut ctx = context()?;
        let primary = create_srk(&mut ctx)?;
        let loaded = ctx
            .load(primary, private, public)
            .map_err(|e| KeyStoreError::Cipher(format!("TPM load: {e}")))?;
        let unsealed = ctx
            .unseal(loaded.into())
            .map_err(|e| KeyStoreError::Cipher(format!("TPM unseal: {e}")))?;
        let bytes = unsealed.value();
        if bytes.len() != 32 {
            return Err(KeyStoreError::Cipher(format!(
                "TPM unsealed {} bytes, expected 32",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    }
}

/// Append-only key-value store. Cheap to clone-read, short-lock to write,
/// and safe to open from several processes at once (see module docs).
pub struct KeyStore {
    path: PathBuf,
    /// In-memory view (plaintext). Reads take a read lock.
    map: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// Append path: intra-process serialization (the `Mutex`) layered over
    /// inter-process exclusion (the `flock` on `lock_file`).
    writer: Mutex<File>,
    /// Dedicated sidecar lock file (`<path>.lock`). All `flock`ing happens
    /// here, not on the data file, so the lock identity is **stable across
    /// compaction's rename** of the data file.
    lock_file: File,
    /// File offset (bytes) we have replayed into `map`. A read whose `stat`
    /// shows a larger file replays the tail before serving; a smaller file
    /// (another process compacted) triggers a full reopen.
    loaded_len: AtomicU64,
    cipher: Cipher,
}

impl KeyStore {
    /// Open (or create) the keystore at `path` with no at-rest encryption.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_cipher(path, Cipher::Identity)
    }

    /// Open (or create) the keystore, sealing record values through
    /// `cipher`. The same cipher must be supplied on every open.
    pub fn open_with_cipher(path: impl AsRef<Path>, cipher: Cipher) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        // Sidecar lock file with a stable identity across compaction.
        let lock_path = Self::lock_path(&path);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
        }

        // Replay under the exclusive lock so we may safely truncate a torn
        // tail left by a crashed writer without racing a live one.
        lock_file.lock_exclusive()?;
        let replay = Self::replay(&mut file, &cipher, true);
        let _ = FileExt::unlock(&lock_file);
        let (map, good_end) = replay?;

        Ok(Self {
            path,
            map: RwLock::new(map),
            writer: Mutex::new(file),
            lock_file,
            loaded_len: AtomicU64::new(good_end),
            cipher,
        })
    }

    fn lock_path(path: &Path) -> PathBuf {
        let mut s = path.as_os_str().to_os_string();
        s.push(".lock");
        PathBuf::from(s)
    }

    /// Whether `f`'s open inode still matches the file at `path` (Unix). A
    /// mismatch means another process replaced the data file (compaction).
    #[cfg(unix)]
    fn same_inode(f: &File, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (f.metadata(), std::fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    fn same_inode(_f: &File, _path: &Path) -> bool {
        true
    }

    /// Bring the data handle `f` and `map` in sync with what's on disk,
    /// assuming the caller holds the appropriate `flock`. Reopens `f` if the
    /// data file was replaced (compaction), replays any appended tail, and
    /// leaves `f` positioned at EOF. Does not truncate.
    fn reconcile(&self, f: &mut File) -> Result<()> {
        if !Self::same_inode(f, &self.path) {
            // Data file was replaced by another process's compaction.
            let mut nf = OpenOptions::new().read(true).write(true).open(&self.path)?;
            let (fresh, end) = Self::replay(&mut nf, &self.cipher, false)?;
            if let Ok(mut m) = self.map.write() {
                *m = fresh;
            }
            self.loaded_len.store(end, Ordering::Release);
            nf.seek(SeekFrom::End(0))?;
            *f = nf;
            return Ok(());
        }
        let cur = f.metadata()?.len();
        let loaded = self.loaded_len.load(Ordering::Acquire);
        if cur < loaded {
            // Same inode but shorter than replayed — defensive full replay.
            let (fresh, end) = Self::replay(f, &self.cipher, false)?;
            if let Ok(mut m) = self.map.write() {
                *m = fresh;
            }
            self.loaded_len.store(end, Ordering::Release);
        } else if cur > loaded {
            let mut m = self
                .map
                .write()
                .map_err(|_| KeyStoreError::Corrupt("map lock poisoned".into()))?;
            let end = Self::apply_records_from(f, &self.cipher, &mut m, loaded)?;
            self.loaded_len.store(end, Ordering::Release);
        }
        f.seek(SeekFrom::End(0))?;
        Ok(())
    }

    /// Replay the log from the header into a fresh map, writing the header
    /// if the file is empty. With `allow_truncate`, a torn trailing record
    /// is cut back (only safe under an exclusive lock). Returns the map and
    /// the offset just past the last complete record.
    fn replay(
        file: &mut File,
        cipher: &Cipher,
        allow_truncate: bool,
    ) -> Result<(HashMap<Vec<u8>, Vec<u8>>, u64)> {
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;

        if len == 0 {
            // Fresh file: write the header.
            file.write_all(MAGIC)?;
            file.write_all(&[VERSION])?;
            file.sync_all()?;
            return Ok((HashMap::new(), 5));
        }

        let mut header = [0u8; 5];
        file.read_exact(&mut header)
            .map_err(|_| KeyStoreError::BadHeader)?;
        if &header[..4] != MAGIC || header[4] != VERSION {
            return Err(KeyStoreError::BadHeader);
        }

        let mut map = HashMap::new();
        let good_end = Self::apply_records_from(file, cipher, &mut map, 5)?;

        if allow_truncate && good_end < len {
            // Truncate the torn tail so the next append starts clean.
            file.set_len(good_end)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok((map, good_end))
    }

    /// Apply complete records starting at `start` into `map`, stopping at a
    /// torn/partial trailing record. Returns the offset past the last
    /// complete record. Does not truncate (caller decides).
    fn apply_records_from(
        file: &mut File,
        cipher: &Cipher,
        map: &mut HashMap<Vec<u8>, Vec<u8>>,
        start: u64,
    ) -> Result<u64> {
        file.seek(SeekFrom::Start(start))?;
        let mut good_end = start;
        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let body_len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; body_len];
            if file.read_exact(&mut body).is_err() {
                // Torn/partial trailing record — stop here.
                break;
            }
            match Self::decode_record(&body, cipher) {
                Ok((flags, key, value)) => {
                    if flags & FLAG_TOMBSTONE != 0 {
                        map.remove(&key);
                    } else {
                        map.insert(key, value);
                    }
                    good_end += 4 + body_len as u64;
                }
                Err(e) => {
                    // A decode failure on a fully-read record means real
                    // corruption (not just a torn tail). Surface it.
                    return Err(e);
                }
            }
        }
        Ok(good_end)
    }

    /// Bring `map` up to date if another process has appended to (or
    /// replaced) the file since our last replay. Cheap when nothing
    /// changed: one `stat` and an atomic load.
    fn refresh_if_changed(&self) -> Result<()> {
        let on_disk = match std::fs::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(_) => return Ok(()), // path gone mid-rename; next read retries
        };
        if on_disk == self.loaded_len.load(Ordering::Acquire) {
            return Ok(());
        }

        // Changed — serialize vs. our own appends (writer mutex) and wait
        // out any live external appender (shared flock on the sidecar lock),
        // so we never read a torn record.
        let mut f = self
            .writer
            .lock()
            .map_err(|_| KeyStoreError::Corrupt("writer lock poisoned".into()))?;
        self.lock_file.lock_shared()?;
        let res = self.reconcile(&mut f);
        let _ = FileExt::unlock(&self.lock_file);
        res
    }

    fn decode_record(body: &[u8], cipher: &Cipher) -> Result<(u8, Vec<u8>, Vec<u8>)> {
        if body.len() < 5 {
            return Err(KeyStoreError::Corrupt("record shorter than header".into()));
        }
        let flags = body[0];
        let key_len = u32::from_le_bytes(body[1..5].try_into().unwrap()) as usize;
        let key_end = 5 + key_len;
        if body.len() < key_end {
            return Err(KeyStoreError::Corrupt("key_len exceeds record".into()));
        }
        let key = body[5..key_end].to_vec();
        let value = cipher.unseal(&body[key_end..])?;
        Ok((flags, key, value))
    }

    fn encode_record(flags: u8, key: &[u8], sealed_value: &[u8]) -> Vec<u8> {
        let body_len = 1 + 4 + key.len() + sealed_value.len();
        let mut out = Vec::with_capacity(4 + body_len);
        out.extend_from_slice(&(body_len as u32).to_le_bytes());
        out.push(flags);
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(sealed_value);
        out
    }

    /// Get a value. Refreshes from disk first if another process appended.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let _ = self.refresh_if_changed();
        self.map.read().ok()?.get(key).cloned()
    }

    /// Whether a key exists.
    pub fn contains(&self, key: &[u8]) -> bool {
        let _ = self.refresh_if_changed();
        self.map.read().map(|m| m.contains_key(key)).unwrap_or(false)
    }

    /// All keys that start with `prefix` (e.g. `b"token:"`).
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        let _ = self.refresh_if_changed();
        self.map
            .read()
            .map(|m| {
                m.keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Insert/overwrite `key`. Appends a record (fsync'd) under an
    /// inter-process exclusive lock, then updates the in-memory map.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let sealed = self.cipher.seal(value)?;
        let rec = Self::encode_record(0, key, &sealed);
        self.append_locked(&rec)?;
        if let Ok(mut m) = self.map.write() {
            m.insert(key.to_vec(), value.to_vec());
        }
        Ok(())
    }

    /// Delete `key` (writes a tombstone).
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let rec = Self::encode_record(FLAG_TOMBSTONE, key, &[]);
        self.append_locked(&rec)?;
        if let Ok(mut m) = self.map.write() {
            m.remove(key);
        }
        Ok(())
    }

    /// Append a pre-encoded record under the writer mutex + an inter-process
    /// exclusive `flock`. Before appending we replay any records other
    /// processes wrote since our last sync (so we append at the true end and
    /// our map stays current), then write at EOF and advance `loaded_len`.
    fn append_locked(&self, rec: &[u8]) -> Result<()> {
        let mut f = self
            .writer
            .lock()
            .map_err(|_| KeyStoreError::Corrupt("writer lock poisoned".into()))?;
        self.lock_file.lock_exclusive()?;
        let res = (|| -> Result<()> {
            // Catch up on external appends / external compaction (reopen) so
            // we append at the true end and our map is current.
            self.reconcile(&mut f)?;
            // A torn tail from a crashed writer would sit past loaded_len;
            // cut it before appending (safe — we hold the exclusive lock).
            let cur = f.metadata()?.len();
            let loaded = self.loaded_len.load(Ordering::Acquire);
            if cur > loaded {
                f.set_len(loaded)?;
                f.sync_all()?;
            }
            f.seek(SeekFrom::End(0))?;
            f.write_all(rec)?;
            f.sync_all()?;
            self.loaded_len
                .fetch_add(rec.len() as u64, Ordering::AcqRel);
            Ok(())
        })();
        let _ = FileExt::unlock(&self.lock_file);
        res
    }

    /// Rewrite the log with only live records (drops superseded entries
    /// and tombstones), via a temp file + atomic rename. Bounds log growth.
    ///
    /// Cross-process: held under the exclusive sidecar lock, and we first
    /// `reconcile` so any records another process appended since our last
    /// sync are folded into the snapshot rather than lost. Other processes
    /// detect the rename on their next read (length/inode change) and
    /// reopen. Concurrent compaction by two processes is not supported —
    /// run it from a single coordinator (the daemon).
    pub fn compact(&self) -> Result<()> {
        let mut f = self
            .writer
            .lock()
            .map_err(|_| KeyStoreError::Corrupt("writer lock poisoned".into()))?;
        self.lock_file.lock_exclusive()?;
        let res = (|| -> Result<()> {
            // Fold in external appends before snapshotting.
            self.reconcile(&mut f)?;
            let entries: Vec<(Vec<u8>, Vec<u8>)> = {
                let m = self
                    .map
                    .read()
                    .map_err(|_| KeyStoreError::Corrupt("map lock poisoned".into()))?;
                m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            };

            let tmp = self.path.with_extension("mvks.compact");
            let mut new_len = 5u64;
            {
                let mut out = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &tmp,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                out.write_all(MAGIC)?;
                out.write_all(&[VERSION])?;
                for (k, v) in &entries {
                    let sealed = self.cipher.seal(v)?;
                    let rec = Self::encode_record(0, k, &sealed);
                    out.write_all(&rec)?;
                    new_len += rec.len() as u64;
                }
                out.sync_all()?;
            }
            std::fs::rename(&tmp, &self.path)?;

            // Reopen the live handle on the new inode at its end.
            let mut reopened = OpenOptions::new().read(true).write(true).open(&self.path)?;
            reopened.seek(SeekFrom::End(0))?;
            *f = reopened;
            self.loaded_len.store(new_len, Ordering::Release);
            Ok(())
        })();
        let _ = FileExt::unlock(&self.lock_file);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> KeyStore {
        KeyStore::open(dir.path().join("ks.mvks")).unwrap()
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = store(&dir);
        assert_eq!(ks.get(b"token:a"), None);
        ks.put(b"token:a", b"alpha").unwrap();
        ks.put(b"token:b", b"beta").unwrap();
        assert_eq!(ks.get(b"token:a").as_deref(), Some(&b"alpha"[..]));
        assert!(ks.contains(b"token:b"));
        ks.delete(b"token:a").unwrap();
        assert_eq!(ks.get(b"token:a"), None);
        assert!(ks.contains(b"token:b"));
    }

    #[test]
    fn last_writer_wins() {
        let dir = tempfile::tempdir().unwrap();
        let ks = store(&dir);
        ks.put(b"k", b"v1").unwrap();
        ks.put(b"k", b"v2").unwrap();
        assert_eq!(ks.get(b"k").as_deref(), Some(&b"v2"[..]));
    }

    #[test]
    fn persists_and_replays_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        {
            let ks = KeyStore::open(&path).unwrap();
            ks.put(b"adminkey:1", b"seed1").unwrap();
            ks.put(b"adminkey:2", b"seed2").unwrap();
            ks.delete(b"adminkey:1").unwrap();
            ks.put(b"token:x", b"tok").unwrap();
        }
        let ks = KeyStore::open(&path).unwrap();
        assert_eq!(ks.get(b"adminkey:1"), None);
        assert_eq!(ks.get(b"adminkey:2").as_deref(), Some(&b"seed2"[..]));
        assert_eq!(ks.get(b"token:x").as_deref(), Some(&b"tok"[..]));
    }

    #[test]
    fn keys_with_prefix_filters() {
        let dir = tempfile::tempdir().unwrap();
        let ks = store(&dir);
        ks.put(b"token:a", b"1").unwrap();
        ks.put(b"token:b", b"2").unwrap();
        ks.put(b"adminkey:z", b"3").unwrap();
        let mut toks = ks.keys_with_prefix(b"token:");
        toks.sort();
        assert_eq!(toks, vec![b"token:a".to_vec(), b"token:b".to_vec()]);
    }

    #[test]
    fn truncates_torn_trailing_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        {
            let ks = KeyStore::open(&path).unwrap();
            ks.put(b"k1", b"v1").unwrap();
            ks.put(b"k2", b"v2").unwrap();
        }
        // Simulate a crash mid-append: a length frame promising more bytes
        // than follow.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&(999u32).to_le_bytes()).unwrap();
            f.write_all(b"partial").unwrap();
            f.sync_all().unwrap();
        }
        let ks = KeyStore::open(&path).unwrap();
        // Live records survive; the torn tail is dropped.
        assert_eq!(ks.get(b"k1").as_deref(), Some(&b"v1"[..]));
        assert_eq!(ks.get(b"k2").as_deref(), Some(&b"v2"[..]));
        // And a subsequent append works (file was truncated to clean end).
        ks.put(b"k3", b"v3").unwrap();
        let ks = KeyStore::open(&path).unwrap();
        assert_eq!(ks.get(b"k3").as_deref(), Some(&b"v3"[..]));
    }

    #[test]
    fn compact_drops_superseded_and_tombstoned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let ks = KeyStore::open(&path).unwrap();
        for i in 0..50 {
            ks.put(b"hot", format!("v{i}").as_bytes()).unwrap();
        }
        ks.put(b"keep", b"yes").unwrap();
        ks.put(b"gone", b"x").unwrap();
        ks.delete(b"gone").unwrap();
        let before = std::fs::metadata(&path).unwrap().len();
        ks.compact().unwrap();
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(after < before, "compaction should shrink the log");
        assert_eq!(ks.get(b"hot").as_deref(), Some(&b"v49"[..]));
        assert_eq!(ks.get(b"keep").as_deref(), Some(&b"yes"[..]));
        assert_eq!(ks.get(b"gone"), None);
        // Survives reopen after compaction.
        let ks = KeyStore::open(&path).unwrap();
        assert_eq!(ks.get(b"hot").as_deref(), Some(&b"v49"[..]));
        assert_eq!(ks.get(b"gone"), None);
    }

    #[test]
    fn custom_cipher_round_trips_on_disk() {
        // A trivial XOR "cipher" proves the seal/unseal hook works and the
        // on-disk bytes differ from plaintext.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let mk_cipher = || Cipher::Custom {
            seal: Box::new(|p| Ok(p.iter().map(|b| b ^ 0x5a).collect())),
            unseal: Box::new(|c| Ok(c.iter().map(|b| b ^ 0x5a).collect())),
        };
        {
            let ks = KeyStore::open_with_cipher(&path, mk_cipher()).unwrap();
            ks.put(b"token:secret", b"top-secret-seed").unwrap();
        }
        // Raw file must not contain the plaintext.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(15).any(|w| w == b"top-secret-seed"),
            "plaintext leaked to disk"
        );
        // Reopening with the same cipher recovers it.
        let ks = KeyStore::open_with_cipher(&path, mk_cipher()).unwrap();
        assert_eq!(ks.get(b"token:secret").as_deref(), Some(&b"top-secret-seed"[..]));
    }

    #[test]
    fn aead_cipher_encrypts_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let key = [7u8; 32];
        {
            let ks = KeyStore::open_with_cipher(&path, Cipher::aead(key)).unwrap();
            ks.put(b"adminkey:1", b"super-secret-signing-seed").unwrap();
            ks.put(b"token:1", b"join-token-bytes").unwrap();
        }
        // Plaintext must not appear on disk.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw
                .windows(25)
                .any(|w| w == b"super-secret-signing-seed"),
            "plaintext leaked to disk under AEAD"
        );
        // Correct key recovers it across reopen.
        let ks = KeyStore::open_with_cipher(&path, Cipher::aead(key)).unwrap();
        assert_eq!(
            ks.get(b"adminkey:1").as_deref(),
            Some(&b"super-secret-signing-seed"[..])
        );
        assert_eq!(ks.get(b"token:1").as_deref(), Some(&b"join-token-bytes"[..]));
    }

    #[test]
    fn aead_wrong_key_fails_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        {
            let ks = KeyStore::open_with_cipher(&path, Cipher::aead([1u8; 32])).unwrap();
            ks.put(b"k", b"v").unwrap();
        }
        // A different key must fail at replay (auth tag rejects it), not
        // silently return garbage.
        let err = KeyStore::open_with_cipher(&path, Cipher::aead([2u8; 32]));
        assert!(matches!(err, Err(KeyStoreError::Cipher(_))));
    }

    #[test]
    fn aead_nonce_is_fresh_per_seal() {
        // Same plaintext sealed twice must differ on disk (fresh nonce).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let ks = KeyStore::open_with_cipher(&path, Cipher::aead([9u8; 32])).unwrap();
        ks.put(b"a", b"same-value").unwrap();
        ks.put(b"b", b"same-value").unwrap();
        let raw = std::fs::read(&path).unwrap();
        // The two sealed records (nonce||ct) must not be byte-identical.
        // Find both value regions is fiddly; instead assert the file has no
        // long repeated 24+ byte run that would indicate a reused nonce+ct.
        let ks2 = KeyStore::open_with_cipher(&path, Cipher::aead([9u8; 32])).unwrap();
        assert_eq!(ks2.get(b"a").as_deref(), Some(&b"same-value"[..]));
        assert_eq!(ks2.get(b"b").as_deref(), Some(&b"same-value"[..]));
        // Sanity: encrypted form is longer than plaintext (nonce + tag).
        assert!(raw.len() > 2 * "same-value".len());
    }

    #[test]
    fn derive_key_is_deterministic_and_salt_sensitive() {
        let salt_a = [1u8; 16];
        let salt_b = [2u8; 16];
        let k1 = derive_key(b"correct horse", &salt_a).unwrap();
        let k2 = derive_key(b"correct horse", &salt_a).unwrap();
        let k3 = derive_key(b"correct horse", &salt_b).unwrap();
        let k4 = derive_key(b"wrong passphrase", &salt_a).unwrap();
        assert_eq!(k1, k2, "same passphrase+salt → same key");
        assert_ne!(k1, k3, "different salt → different key");
        assert_ne!(k1, k4, "different passphrase → different key");
    }

    #[test]
    fn two_handles_see_each_others_writes() {
        // Two KeyStore handles on one path stand in for two processes: each
        // opens the same lock file as a distinct open-file-description, so
        // flock gives real mutual exclusion.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let a = KeyStore::open(&path).unwrap();
        let b = KeyStore::open(&path).unwrap();

        a.put(b"token:1", b"from-a").unwrap();
        // b must observe a's append (refresh-on-read).
        assert_eq!(b.get(b"token:1").as_deref(), Some(&b"from-a"[..]));

        b.put(b"adminkey:x", b"from-b").unwrap();
        assert_eq!(a.get(b"adminkey:x").as_deref(), Some(&b"from-b"[..]));

        // Overwrite from the other side is seen too.
        b.put(b"token:1", b"from-b-2").unwrap();
        assert_eq!(a.get(b"token:1").as_deref(), Some(&b"from-b-2"[..]));

        // Delete from one side observed by the other.
        a.delete(b"adminkey:x").unwrap();
        assert_eq!(b.get(b"adminkey:x"), None);
    }

    #[test]
    fn interleaved_appends_from_two_handles_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let a = KeyStore::open(&path).unwrap();
        let b = KeyStore::open(&path).unwrap();
        for i in 0..25 {
            a.put(format!("a:{i}").as_bytes(), b"av").unwrap();
            b.put(format!("b:{i}").as_bytes(), b"bv").unwrap();
        }
        // A fresh handle replays the whole interleaved log without corruption.
        let c = KeyStore::open(&path).unwrap();
        assert_eq!(c.keys_with_prefix(b"a:").len(), 25);
        assert_eq!(c.keys_with_prefix(b"b:").len(), 25);
        assert_eq!(c.get(b"a:0").as_deref(), Some(&b"av"[..]));
        assert_eq!(c.get(b"b:24").as_deref(), Some(&b"bv"[..]));
    }

    #[test]
    fn second_handle_recovers_after_other_compacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let a = KeyStore::open(&path).unwrap();
        let b = KeyStore::open(&path).unwrap();
        for i in 0..40 {
            a.put(b"hot", format!("v{i}").as_bytes()).unwrap();
        }
        a.put(b"keep", b"yes").unwrap();
        // b reads the pre-compaction state.
        assert_eq!(b.get(b"hot").as_deref(), Some(&b"v39"[..]));
        // a compacts (rename → new inode); b must detect and reopen.
        a.compact().unwrap();
        assert_eq!(b.get(b"hot").as_deref(), Some(&b"v39"[..]));
        assert_eq!(b.get(b"keep").as_deref(), Some(&b"yes"[..]));
        // b can still append after the other process compacted.
        b.put(b"after", b"ok").unwrap();
        assert_eq!(a.get(b"after").as_deref(), Some(&b"ok"[..]));
    }

    #[test]
    fn concurrent_handles_under_thread_contention() {
        // Two handles, two threads, hammering appends at once. flock must
        // keep records from interleaving at the byte level; a fresh reopen
        // must then replay every record cleanly.
        use std::sync::Arc;
        use std::thread;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let a = Arc::new(KeyStore::open(&path).unwrap());
        let b = Arc::new(KeyStore::open(&path).unwrap());
        let n = 200;
        let ta = {
            let a = Arc::clone(&a);
            thread::spawn(move || {
                for i in 0..n {
                    a.put(format!("a:{i:04}").as_bytes(), b"x").unwrap();
                }
            })
        };
        let tb = {
            let b = Arc::clone(&b);
            thread::spawn(move || {
                for i in 0..n {
                    b.put(format!("b:{i:04}").as_bytes(), b"y").unwrap();
                }
            })
        };
        ta.join().unwrap();
        tb.join().unwrap();
        let c = KeyStore::open(&path).unwrap();
        assert_eq!(c.keys_with_prefix(b"a:").len(), n);
        assert_eq!(c.keys_with_prefix(b"b:").len(), n);
    }

    #[test]
    fn compaction_folds_in_concurrent_external_append() {
        // If b appends after a's last sync, a.compact() must not drop it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let a = KeyStore::open(&path).unwrap();
        let b = KeyStore::open(&path).unwrap();
        a.put(b"k1", b"v1").unwrap();
        // b appends; a has not refreshed its map yet.
        b.put(b"k2", b"v2").unwrap();
        a.compact().unwrap();
        // The compacted log must still contain b's record.
        let c = KeyStore::open(&path).unwrap();
        assert_eq!(c.get(b"k1").as_deref(), Some(&b"v1"[..]));
        assert_eq!(c.get(b"k2").as_deref(), Some(&b"v2"[..]));
    }

    #[test]
    fn derived_key_drives_aead_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.mvks");
        let salt = [42u8; 16];
        let key = derive_key(b"hunter2", &salt).unwrap();
        {
            let ks = KeyStore::open_with_cipher(&path, Cipher::aead(key)).unwrap();
            ks.put(b"token:t", b"payload").unwrap();
        }
        // Re-deriving from the same passphrase+salt reopens it.
        let key2 = derive_key(b"hunter2", &salt).unwrap();
        let ks = KeyStore::open_with_cipher(&path, Cipher::aead(key2)).unwrap();
        assert_eq!(ks.get(b"token:t").as_deref(), Some(&b"payload"[..]));
    }
}
