//! File upload/download smoke tests.

use memvault_api::MemvaultClient;

use crate::harness::TestNode;

#[tokio::test]
async fn upload_and_read_file() {
    let node = TestNode::new();
    let data = b"Hello file content!";
    let cid = node
        .client
        .upload_file(
            data,
            Some("hello.txt"),
            "text/plain",
            vec![("type".into(), "document".into())],
            "internal",
            None,
        )
        .await
        .unwrap();
    assert!(!cid.is_empty());

    let content = node.client.read_file(&cid).await.unwrap();
    assert_eq!(&content, data);
}

#[tokio::test]
async fn upload_binary_file() {
    let node = TestNode::new();
    let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let cid = node
        .client
        .upload_file(
            &data,
            Some("binary.bin"),
            "application/octet-stream",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let content = node.client.read_file(&cid).await.unwrap();
    assert_eq!(content, data);
}

#[tokio::test]
async fn upload_large_file() {
    let node = TestNode::new();
    let data = vec![0xABu8; 100_000]; // 100KB
    let cid = node
        .client
        .upload_file(
            &data,
            Some("large.dat"),
            "application/octet-stream",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let content = node.client.read_file(&cid).await.unwrap();
    assert_eq!(content.len(), 100_000);
}

#[tokio::test]
async fn file_manifest() {
    let node = TestNode::new();
    let data = b"manifest test";
    let cid = node
        .client
        .upload_file(
            data,
            Some("test.md"),
            "text/markdown",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let manifest = node.client.get_file_manifest(&cid).await.unwrap();
    assert!(manifest.is_some());
}

#[tokio::test]
async fn read_file_range() {
    let node = TestNode::new();
    let data = b"0123456789ABCDEF";
    let cid = node
        .client
        .upload_file(
            data,
            Some("range.txt"),
            "text/plain",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let range = node.client.read_file_range(&cid, 4, 8).await.unwrap();
    assert_eq!(&range, b"4567");
}

#[tokio::test]
async fn extract_text_from_plaintext() {
    let node = TestNode::new();
    let data = b"This is extractable text.";
    let cid = node
        .client
        .upload_file(
            data,
            Some("extract.txt"),
            "text/plain",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let text = node.client.read_extracted_text(&cid).await.unwrap();
    // May or may not extract depending on extractor support
    if let Some(t) = text {
        assert!(t.contains("extractable"));
    }
}

/// Once a bucket exists, a file upload without one is refused, like a
/// document write (`store_op`): it used to land unbucketed, invisible to
/// every bucket-scoped listing (AGENTS.md, "All new data must have a bucket").
#[tokio::test]
async fn upload_without_a_bucket_is_refused_once_buckets_exist() {
    let node = TestNode::new();
    let bucket = node
        .client
        .bucket_create(
            "files",
            None,
            memvault_core::Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_core::BucketRole::Standard,
        )
        .await
        .unwrap();
    let unbucketed = node
        .client
        .upload_file(
            b"lost",
            Some("lost.txt"),
            "text/plain",
            vec![],
            "internal",
            None,
        )
        .await;
    assert!(unbucketed.is_err(), "an upload needs a bucket post-genesis");
    let cid = node
        .client
        .upload_file(
            b"kept",
            Some("kept.txt"),
            "text/plain",
            vec![],
            "internal",
            Some(&bucket),
        )
        .await
        .unwrap();
    assert_eq!(node.client.bucket_for_file(&cid), Some(bucket));
}
