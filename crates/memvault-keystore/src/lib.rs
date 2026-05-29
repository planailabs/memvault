//! `memvault-keystore` — a small, lock-free-read, append-only key-value
//! store for tokens and key material, deliberately **separate from the
//! redb blockstore**.
//!
//! ## Why a separate store
//!
//! redb takes a single exclusive write transaction for the whole
//! database, so issuing tokens or reading key material contends with the
//! daemon's long-running block writes. This store decouples that: reads
//! are served from an in-memory map (an `RwLock` read, never touching the
//! file or the blockstore lock), and writes are short appends to a log.
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
use std::sync::{Mutex, RwLock};

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

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cipher::Identity => write!(f, "Cipher::Identity"),
            Cipher::Custom { .. } => write!(f, "Cipher::Custom"),
        }
    }
}

/// Append-only key-value store. Cheap to clone-read, short-lock to write.
pub struct KeyStore {
    path: PathBuf,
    /// In-memory view (plaintext). Reads take a read lock; never touch disk.
    map: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// Append path: serialized writers + fsync. Reads never wait on this.
    writer: Mutex<File>,
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

        let map = Self::replay(&mut file, &cipher)?;

        Ok(Self {
            path,
            map: RwLock::new(map),
            writer: Mutex::new(file),
            cipher,
        })
    }

    /// Replay the log into a map, writing the header if the file is empty
    /// and truncating any torn trailing record left by a crash.
    fn replay(file: &mut File, cipher: &Cipher) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;

        if len == 0 {
            // Fresh file: write the header.
            file.write_all(MAGIC)?;
            file.write_all(&[VERSION])?;
            file.sync_all()?;
            return Ok(HashMap::new());
        }

        let mut header = [0u8; 5];
        file.read_exact(&mut header)
            .map_err(|_| KeyStoreError::BadHeader)?;
        if &header[..4] != MAGIC || header[4] != VERSION {
            return Err(KeyStoreError::BadHeader);
        }

        let mut map = HashMap::new();
        // Offset of the byte just past the last *complete* record. A torn
        // tail is truncated back to here.
        let mut good_end = 5u64;
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
                // Torn trailing record — stop and truncate below.
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

        if good_end < len {
            // Truncate the torn tail so the next append starts clean.
            file.set_len(good_end)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(map)
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

    /// Get a value. Lock-free vs. writes and the blockstore — a read lock
    /// on the in-memory map only.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.read().ok()?.get(key).cloned()
    }

    /// Whether a key exists.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.map.read().map(|m| m.contains_key(key)).unwrap_or(false)
    }

    /// All keys that start with `prefix` (e.g. `b"token:"`).
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
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

    /// Insert/overwrite `key`. Appends a record (fsync'd) then updates the
    /// in-memory map. Holds the writer lock only for the append.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let sealed = self.cipher.seal(value)?;
        let rec = Self::encode_record(0, key, &sealed);
        {
            let mut f = self.writer.lock().map_err(|_| {
                KeyStoreError::Corrupt("writer lock poisoned".into())
            })?;
            f.write_all(&rec)?;
            f.sync_all()?;
        }
        if let Ok(mut m) = self.map.write() {
            m.insert(key.to_vec(), value.to_vec());
        }
        Ok(())
    }

    /// Delete `key` (writes a tombstone).
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let rec = Self::encode_record(FLAG_TOMBSTONE, key, &[]);
        {
            let mut f = self.writer.lock().map_err(|_| {
                KeyStoreError::Corrupt("writer lock poisoned".into())
            })?;
            f.write_all(&rec)?;
            f.sync_all()?;
        }
        if let Ok(mut m) = self.map.write() {
            m.remove(key);
        }
        Ok(())
    }

    /// Rewrite the log with only live records (drops superseded entries
    /// and tombstones), via a temp file + atomic rename. Bounds log growth.
    pub fn compact(&self) -> Result<()> {
        // Snapshot live entries.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let m = self
                .map
                .read()
                .map_err(|_| KeyStoreError::Corrupt("map lock poisoned".into()))?;
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        // Hold the writer lock across the swap so no append races the rename.
        let mut f = self
            .writer
            .lock()
            .map_err(|_| KeyStoreError::Corrupt("writer lock poisoned".into()))?;

        let tmp = self.path.with_extension("mvks.compact");
        {
            let mut out = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            out.write_all(MAGIC)?;
            out.write_all(&[VERSION])?;
            for (k, v) in &entries {
                let sealed = self.cipher.seal(v)?;
                out.write_all(&Self::encode_record(0, k, &sealed))?;
            }
            out.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;

        // Reopen the live file handle at its end for subsequent appends.
        let mut reopened = OpenOptions::new().read(true).write(true).open(&self.path)?;
        reopened.seek(SeekFrom::End(0))?;
        *f = reopened;
        Ok(())
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
}
