//! Media extraction pipeline smoke tests: PDF page pre-rendering through
//! the WASM pipeline, unavailable-capability handling, and peer serving
//! of synced page_render annotations.

use std::sync::Arc;

use tokio::sync::RwLock;

use memvault_api::extraction_config::ExtractionConfig;
use memvault_api::types::MediaJobStatus;
use memvault_api::{EventBus, LocalClient, MemvaultClient};
use memvault_query::QuotaManager;
use memvault_store::MemvaultStore;

/// One-page PDF fixture with embedded "Hello Memvault" text (shared with
/// the pdfrender guest's own tests).
const SIMPLE_PDF: &[u8] =
    include_bytes!("../../../memvault-extract-guest-pdfrender/tests/fixtures/simple.pdf");

fn open_temp_store(dir: &tempfile::TempDir, name: &str) -> Arc<MemvaultStore> {
    let path = dir.path().join(format!("{name}.redb"));
    Arc::new(MemvaultStore::open(&path).unwrap())
}

fn make_client(store: Arc<MemvaultStore>) -> Arc<LocalClient> {
    let client = LocalClient::new(
        store,
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        vec![0u8; 32],
        vec![0u8; 32],
    );
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    Arc::new(client)
}

/// Default config: page rendering enabled out of the box; whisper/OCR
/// unavailable (no models_dir).
fn install_default_pipeline(client: &Arc<LocalClient>) {
    client.install_extraction_pipeline(ExtractionConfig::default());
}

async fn wait_for_render_done(
    client: &Arc<LocalClient>,
    cid: &[u8],
) -> memvault_api::types::PageRenderInfo {
    for _ in 0..300 {
        let info = client.read_page_render(cid).await.unwrap();
        match info.status {
            MediaJobStatus::Pending => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            _ => return info,
        }
    }
    panic!("page render did not finish within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdf_page_render_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_temp_store(&dir, "render");
    let client = make_client(Arc::clone(&store));
    install_default_pipeline(&client);

    let cid = client
        .upload_file(
            SIMPLE_PDF,
            Some("simple.pdf"),
            "application/pdf",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let info = wait_for_render_done(&client, &cid).await;
    assert_eq!(info.status, MediaJobStatus::Done, "error: {:?}", info.error);
    assert_eq!(info.page_count, 1);
    let dims = info.pages[0];
    assert_eq!(dims.page_no, 1);
    // 144 dpi on US Letter = 2× 612×792 points.
    assert!(dims.width > 1000 && dims.height > 1400, "dims: {dims:?}");

    // Page image is a PNG.
    let (image, mime) = client.read_page_image(&cid, 1).await.unwrap().unwrap();
    assert_eq!(mime, "image/png");
    assert_eq!(&image[..4], &[0x89, b'P', b'N', b'G']);

    // Text layer carries the embedded words in pixel coords.
    let layer = client.read_page_text_layer(&cid, 1).await.unwrap().unwrap();
    assert_eq!(layer.width, dims.width);
    assert!(layer.words.iter().any(|w| w.text.contains("Hello")));
    let hello = layer.words.iter().find(|w| w.text.contains("Hello")).unwrap();
    assert!(hello.x >= 0.0 && hello.x < dims.width as f32);
    assert!(hello.h > 0.0);

    // Unknown page → None, not an error.
    assert!(client.read_page_image(&cid, 99).await.unwrap().is_none());

    // Unified extraction endpoint still reports the fast text path.
    let extraction = client.read_extraction(&cid).await.unwrap();
    assert_eq!(extraction.status, MediaJobStatus::Done);
    assert!(extraction.text.unwrap_or_default().contains("Hello"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audio_without_model_is_unavailable_not_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_temp_store(&dir, "audio");
    let client = make_client(Arc::clone(&store));
    install_default_pipeline(&client);

    // Minimal valid WAV header + a few silent samples.
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&36u32.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // mono
    wav.extend_from_slice(&16000u32.to_le_bytes());
    wav.extend_from_slice(&32000u32.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&0u32.to_le_bytes());

    let cid = client
        .upload_file(&wav, Some("note.wav"), "audio/wav", vec![], "internal", None)
        .await
        .unwrap();

    // Whisper is not configured → unavailable with a reason; never a
    // cached failure (so enabling it later works without cleanup).
    let info = client.read_extraction(&cid).await.unwrap();
    assert_eq!(info.status, MediaJobStatus::Unavailable);
    assert!(info.error.unwrap().contains("models_dir not set"));

    // Stable across repeated reads — and read_extracted_text stays None.
    let info = client.read_extraction(&cid).await.unwrap();
    assert_eq!(info.status, MediaJobStatus::Unavailable);
    assert_eq!(client.read_extracted_text(&cid).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn render_disabled_by_config() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_temp_store(&dir, "disabled");
    let client = make_client(Arc::clone(&store));
    let mut cfg = ExtractionConfig::default();
    cfg.render.enabled = false;
    client.install_extraction_pipeline(cfg);

    let cid = client
        .upload_file(
            SIMPLE_PDF,
            Some("simple.pdf"),
            "application/pdf",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let info = client.read_page_render(&cid).await.unwrap();
    assert_eq!(info.status, MediaJobStatus::Unavailable);
    assert!(info.error.unwrap().contains("render.enabled"));
    // Nothing cached: text extraction (inline path) is unaffected.
    assert!(client.read_extracted_text(&cid).await.unwrap().is_some());
}

/// A peer that holds the synced blocks serves page renders without its
/// own pipeline — annotations are the durable, cluster-wide record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_serves_synced_page_render() {
    let dir = tempfile::tempdir().unwrap();
    let store1 = open_temp_store(&dir, "origin");
    let store2 = open_temp_store(&dir, "peer");

    let client1 = make_client(Arc::clone(&store1));
    install_default_pipeline(&client1);

    let cid = client1
        .upload_file(
            SIMPLE_PDF,
            Some("simple.pdf"),
            "application/pdf",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();
    let info = wait_for_render_done(&client1, &cid).await;
    assert_eq!(info.status, MediaJobStatus::Done);

    // Simulate full sync: copy every block and reindex envelopes (the
    // same canonical path the swarm uses on ingest).
    for (block_cid, data) in store1.iter_blocks().unwrap() {
        store2.put_block(&block_cid, &data).unwrap();
        let _ = store2.reindex_block(&block_cid, &data);
    }

    // Peer client: NO pipeline installed — must serve from annotations.
    let client2 = make_client(Arc::clone(&store2));
    let info2 = client2.read_page_render(&cid).await.unwrap();
    assert_eq!(info2.status, MediaJobStatus::Done);
    assert_eq!(info2.page_count, 1);

    let (image, _) = client2.read_page_image(&cid, 1).await.unwrap().unwrap();
    assert_eq!(&image[..4], &[0x89, b'P', b'N', b'G']);
    let layer = client2.read_page_text_layer(&cid, 1).await.unwrap().unwrap();
    assert!(layer.words.iter().any(|w| w.text.contains("Hello")));
}
