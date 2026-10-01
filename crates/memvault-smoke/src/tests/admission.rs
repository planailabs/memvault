//! One admission path: a block written locally, the same block arriving
//! from a peer, and the block after `rebuild_store` index identically, and
//! the sync gate verifies what it admits (sign-everything, block-ingestion).

use std::collections::BTreeSet;

use memvault_api::MemvaultClient;
use memvault_api::admission::{Admitted, SyncGate};
use memvault_auth::{Action, GrantAudience};
use memvault_core::classification::Classification;
use memvault_core::{BucketId, BucketRole, ClusterId, DocId, PeerId, Visibility, cid_from_bytes};
use memvault_doc::Document;
use memvault_store::MemvaultStore;

use crate::harness::TestNode;

fn admin_of(node: &TestNode) -> ed25519_dalek::SigningKey {
    node.client
        .admin_signing_key()
        .expect("test node holds an admin key")
}

fn gate<'a>(store: &'a MemvaultStore, anchor: &TestNode) -> SyncGate<'a> {
    SyncGate::new(
        store,
        anchor.cluster_id.0,
        Some(admin_of(anchor).verifying_key().to_bytes()),
    )
}

fn random_key() -> ed25519_dalek::SigningKey {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn node_att(signer: &ed25519_dalek::SigningKey, cluster: &ClusterId, member: [u8; 32]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut att = memvault_auth::NodeAttestation {
        cluster_id: cluster.clone(),
        member: PeerId(member.to_vec()),
        not_after_ns: u64::MAX,
        issued_via: memvault_auth::AttestationOrigin::Direct,
        signature: [0u8; 64],
    };
    att.signature = signer.sign(&att.signing_bytes().unwrap()).to_bytes();
    serde_ipld_dagcbor::to_vec(&att).unwrap()
}

fn tagged(store: &MemvaultStore, scope: &str, label: &str) -> BTreeSet<Vec<u8>> {
    store
        .query_by_tag(scope, label, 0, usize::MAX)
        .unwrap()
        .into_iter()
        .collect()
}

/// Populate a node with one of every bare sigchain record kind plus
/// ordinary content (signed bucket decls, a doc, a file).
async fn populate(a: &TestNode, member: [u8; 32]) -> (BucketId, BucketId, Vec<u8>) {
    let admin = admin_of(a);
    let genesis = memvault_auth::sign_admin_genesis(&admin, a.cluster_id.clone(), 1_000).unwrap();
    memvault_api::sigchain::publish_admin_genesis(&a.client, &genesis).unwrap();
    let att_cid = a.client.attest_node(member).unwrap();
    // Peers trust A's own decls once A's node is attested.
    a.client
        .attest_node(a.client.node_verifying_key().unwrap().to_bytes())
        .unwrap();

    let bucket = a
        .client
        .bucket_create(
            "alpha",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    a.client
        .bucket_rename(&bucket, "alpha-renamed")
        .await
        .unwrap();
    let other = a
        .client
        .bucket_create(
            "beta",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    a.client
        .put_doc(
            Document::new(DocId::random(), "hello".into(), Default::default()),
            vec![("topic".into(), "x".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    a.client
        .upload_file(
            &vec![7u8; 300_000],
            Some("blob.bin"),
            "application/octet-stream",
            vec![],
            "internal",
            Some(&bucket),
        )
        .await
        .unwrap();
    a.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey([5u8; 32]),
            vec![Action::Read],
            3600,
        )
        .await
        .unwrap();
    a.client
        .bucket_merge_sync(&[other.clone()], &bucket)
        .unwrap();

    let token_cid = cid_from_bytes(b"some join token");
    let tc = memvault_auth::sign_token_consumption(
        &admin,
        token_cid,
        PeerId(member.to_vec()),
        2_000,
        cid_from_bytes(&att_cid),
    )
    .unwrap();
    memvault_api::sigchain::publish_token_consumption(&a.client, &tc).unwrap();

    let trust = memvault_auth::BucketTrust {
        bucket_id: bucket.clone(),
        from_cluster: ClusterId::random(),
        to_cluster: a.cluster_id.clone(),
        actions: vec![Action::Read],
        not_after_ns: u64::MAX,
        from_proposal: cid_from_bytes(b"proposal"),
        from_reply: cid_from_bytes(b"reply"),
        signature: [0u8; 64],
    }
    .sign(&admin)
    .unwrap();
    a.client
        .ingest_record(&serde_ipld_dagcbor::to_vec(&trust).unwrap())
        .unwrap();
    (bucket, other, token_cid.to_bytes())
}

/// Copy every block of `from` into `to` through the sync gate; every block
/// must be admitted.
fn sync_all(from: &MemvaultStore, gate: &mut SyncGate<'_>) {
    let mut blocks = from.iter_blocks().unwrap();
    // Signers before what they sign (the real exchange gets there by
    // retrying on the next RBSR round).
    blocks.sort_by_key(|(_, data)| match memvault_auth::sigchain_label_for(data) {
        Some("admin_genesis") => 0,
        Some("admin_admission") | Some("admin_retirement") => 1,
        Some("node_att") => 2,
        _ => 3,
    });
    for (cid, data) in blocks {
        let r = gate.admit(&cid, &data);
        assert!(
            matches!(r, Admitted::Stored { .. }),
            "block {} not admitted: {r:?}",
            hex::encode(&cid)
        );
    }
}

/// Bare records (grants, merges, token redemptions, bucket trusts, admin
/// genesis, attestations) used to be indexed with the writer's clock and
/// local peer on the writing node, and the receiver's clock on a synced
/// copy — so RBSR windows never matched and lookups differed. Now both
/// derive the entries from the record.
#[tokio::test]
async fn local_and_synced_copies_index_identically() {
    let a = TestNode::new();
    let b = TestNode::with_cluster(&a.cluster_id);
    let member = random_key().verifying_key().to_bytes();
    let (bucket, other, token_cid) = populate(&a, member).await;

    let mut g = gate(&b.store, &a);
    sync_all(&a.store, &mut g);

    assert_eq!(
        a.store.range_fingerprint(0, u64::MAX).unwrap(),
        b.store.range_fingerprint(0, u64::MAX).unwrap(),
        "RBSR fingerprint differs between the writer and the synced copy"
    );
    for label in [
        "admin_genesis",
        "node_att",
        "grant",
        "bucket_merge",
        "token_redeem",
        "bucket_trust",
    ] {
        let on_a = tagged(&a.store, "sigchain", label);
        assert!(!on_a.is_empty(), "sigchain/{label} on the writer");
        assert_eq!(
            on_a,
            tagged(&b.store, "sigchain", label),
            "sigchain/{label}"
        );
    }
    for (scope, label) in [
        ("grant", hex::encode(bucket.0)),
        ("bucket_merge", hex::encode(other.0)),
        ("token_redeem", hex::encode(&token_cid)),
        ("kind", "bucket-trust".to_string()),
    ] {
        let on_a = tagged(&a.store, scope, &label);
        assert_eq!(on_a.len(), 1, "{scope}/{label} on the writer");
        assert_eq!(on_a, tagged(&b.store, scope, &label), "{scope}/{label}");
    }
    // The grant is authored by its signer and dated by not_before, not by
    // the writing node's peer id / clock.
    let admin_pk = admin_of(&a).verifying_key().to_bytes();
    let grant_cid = tagged(&a.store, "sigchain", "grant")
        .into_iter()
        .next()
        .unwrap();
    for store in [&a.store, &b.store] {
        assert!(
            store
                .query_by_author(&admin_pk, 0, usize::MAX)
                .unwrap()
                .contains(&grant_cid)
        );
    }

    // A redemption counts against the token's max_uses on every node: the
    // count is derived from the synced TokenConsumption blocks, not only a
    // local counter.
    assert_eq!(b.client.token_consumption_count(&token_cid), 1);

    // The renamed bucket reads the same on both.
    let info_b = b.client.bucket_get(&bucket).await.unwrap().unwrap();
    assert_eq!(info_b.name, "alpha-renamed");
}

/// `rebuild_store` re-derives the same index entries: grant and
/// token-redemption tags survive, and the RBSR fingerprint is unchanged.
#[tokio::test]
async fn rebuild_reproduces_record_indexes() {
    let a = TestNode::new();
    let member = random_key().verifying_key().to_bytes();
    let (bucket, other, token_cid) = populate(&a, member).await;
    let before = a.store.range_fingerprint(0, u64::MAX).unwrap();
    let grants = tagged(&a.store, "grant", &hex::encode(bucket.0));
    let merges = tagged(&a.store, "bucket_merge", &hex::encode(other.0));
    let redeems = tagged(&a.store, "token_redeem", &hex::encode(&token_cid));

    memvault_api::rebuild::rebuild_store(&a.client).unwrap();

    assert_eq!(grants.len(), 1);
    assert_eq!(tagged(&a.store, "grant", &hex::encode(bucket.0)), grants);
    assert_eq!(
        tagged(&a.store, "bucket_merge", &hex::encode(other.0)),
        merges
    );
    assert_eq!(
        tagged(&a.store, "token_redeem", &hex::encode(&token_cid)),
        redeems
    );
    assert_eq!(tagged(&a.store, "sigchain", "grant"), grants);
    assert_eq!(a.store.range_fingerprint(0, u64::MAX).unwrap(), before);
    assert_eq!(
        a.client.list_bucket_grants(&bucket).unwrap().len(),
        1,
        "grant still listed after rebuild"
    );
}

/// A NodeAttestation must be signed by the pinned admin or an admin the
/// admission chain admits; anything else is dropped at the gate, and an
/// admitted one is authored by the verifying admin.
#[tokio::test]
async fn node_attestation_requires_admin_signature() {
    let a = TestNode::new();
    let b = TestNode::with_cluster(&a.cluster_id);
    let admin = admin_of(&a);
    let member = random_key().verifying_key().to_bytes();

    let forged = node_att(&random_key(), &a.cluster_id, member);
    let mut g = gate(&b.store, &a);
    assert!(matches!(
        g.admit(&cid_from_bytes(&forged).to_bytes(), &forged),
        Admitted::Dropped(_)
    ));
    assert!(tagged(&b.store, "sigchain", "node_att").is_empty());

    let genuine = node_att(&admin, &a.cluster_id, member);
    let cid = cid_from_bytes(&genuine).to_bytes();
    assert!(matches!(g.admit(&cid, &genuine), Admitted::Stored { .. }));
    assert!(
        b.store
            .query_by_author(&admin.verifying_key().to_bytes(), 0, usize::MAX)
            .unwrap()
            .contains(&cid),
        "author is the verifying admin"
    );

    // An admin admitted by the anchor may attest too — once its admission
    // is known.
    let co_admin = random_key();
    let attested_by_co = node_att(&co_admin, &a.cluster_id, [9u8; 32]);
    let co_cid = cid_from_bytes(&attested_by_co).to_bytes();
    assert!(matches!(
        g.admit(&co_cid, &attested_by_co),
        Admitted::Dropped(_)
    ));
    let pop = memvault_auth::sign_admin_pop(&co_admin, &a.cluster_id, u64::MAX);
    let adm = memvault_auth::sign_admin_admission(
        &admin,
        co_admin.verifying_key().to_bytes(),
        a.cluster_id.clone(),
        10,
        10,
        u64::MAX,
        None,
        pop,
    )
    .unwrap();
    let adm_bytes = serde_ipld_dagcbor::to_vec(&adm).unwrap();
    assert!(matches!(
        g.admit(&cid_from_bytes(&adm_bytes).to_bytes(), &adm_bytes),
        Admitted::Stored { .. }
    ));
    assert!(matches!(
        g.admit(&co_cid, &attested_by_co),
        Admitted::Stored { .. }
    ));
}

/// The join path used to drop AdminGenesis (no classifier arm) and to
/// re-ingest blocks it already held. The gate admits the pinned admin's
/// genesis (tagged like the local writer), refuses a rival genesis, and
/// skips blocks it holds.
#[tokio::test]
async fn admin_genesis_admitted_and_reingest_is_skipped() {
    let a = TestNode::new();
    let b = TestNode::with_cluster(&a.cluster_id);
    let admin = admin_of(&a);
    let genesis = memvault_auth::sign_admin_genesis(&admin, a.cluster_id.clone(), 5).unwrap();
    let bytes = serde_ipld_dagcbor::to_vec(&genesis).unwrap();
    let cid = cid_from_bytes(&bytes).to_bytes();

    let mut g = gate(&b.store, &a);
    assert!(matches!(g.admit(&cid, &bytes), Admitted::Stored { .. }));
    assert!(matches!(g.admit(&cid, &bytes), Admitted::AlreadyHeld));
    assert_eq!(
        b.store
            .query_by_tag("sigchain", "admin_genesis", 0, usize::MAX)
            .unwrap(),
        vec![cid],
        "one index entry, tagged like publish_admin_genesis"
    );

    let rival = memvault_auth::sign_admin_genesis(&random_key(), a.cluster_id.clone(), 1).unwrap();
    let rival = serde_ipld_dagcbor::to_vec(&rival).unwrap();
    assert!(matches!(
        g.admit(&cid_from_bytes(&rival).to_bytes(), &rival),
        Admitted::Dropped(_)
    ));
}

/// A peer-supplied decl signed by a stranger, dated after the real one,
/// used to move the BUCKETS pointer (any decl overwrote it on arrival).
#[tokio::test]
async fn forged_bucket_decl_does_not_take_over() {
    let a = TestNode::new();
    let bucket = a
        .client
        .bucket_create(
            "real",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    let mut decl = memvault_api::LocalClient::parse_bucket_decl_static(
        &a.store
            .get_block(&a.store.get_bucket(&bucket.0).unwrap().unwrap())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    decl.name = "pwned".into();
    let stranger = random_key();
    let forged = memvault_core::Signed::sign(
        serde_json::json!({ "BucketCreate": decl }),
        &stranger,
        PeerId(stranger.verifying_key().to_bytes().to_vec()),
        vec![],
        vec![],
        vec![
            memvault_core::Tag::new("kind", "bucket-decl"),
            memvault_core::Tag::new("bucket", bucket.to_string()),
        ],
        Visibility::Internal,
        0,
        u64::MAX - 1,
        None,
        Some(bucket.clone()),
        None,
        None,
        None,
    )
    .unwrap();
    let bytes = serde_ipld_dagcbor::to_vec(&forged).unwrap();
    let mut g = gate(&a.store, &a);
    assert!(matches!(
        g.admit(&cid_from_bytes(&bytes).to_bytes(), &bytes),
        Admitted::Stored { .. }
    ));
    assert_eq!(
        a.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        "real"
    );

    // Rebuild doesn't let it win either.
    memvault_api::rebuild::rebuild_store(&a.client).unwrap();
    assert_eq!(
        a.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        "real"
    );
}

/// Renames are signed decl updates; the current decl is picked from all of
/// them, so delivery order doesn't matter, and a node that neither owns the
/// bucket nor is an admin can't rename it.
#[tokio::test]
async fn bucket_decl_updates_are_signed_and_order_independent() {
    let a = TestNode::new();
    let bucket = a
        .client
        .bucket_create(
            "v1",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    a.client.bucket_rename(&bucket, "v2").await.unwrap();
    a.client.bucket_rename(&bucket, "v3").await.unwrap();
    a.client.bucket_archive(&bucket, "done").await.unwrap();
    let final_name = a.client.bucket_get(&bucket).await.unwrap().unwrap().name;
    assert!(final_name.starts_with("[ARCHIVED] v3"), "{final_name}");

    let current = a.store.get_bucket(&bucket.0).unwrap().unwrap();
    let cand = memvault_store::bucket_decl::parse_decl(
        &a.store,
        &current,
        &a.store.get_block(&current).unwrap().unwrap(),
    )
    .unwrap();
    assert!(!cand.signers.is_empty(), "current decl is signed");

    // Deliver every block to B newest-first; B trusts A's node.
    let b = TestNode::with_cluster(&a.cluster_id);
    b.client
        .seed_admin_anchor(admin_of(&a).verifying_key().to_bytes());
    let att = node_att(
        &admin_of(&a),
        &a.cluster_id,
        a.client.node_verifying_key().unwrap().to_bytes(),
    );
    let mut g = gate(&b.store, &a);
    assert!(matches!(
        g.admit(&cid_from_bytes(&att).to_bytes(), &att),
        Admitted::Stored { .. }
    ));
    let mut blocks = a.store.iter_blocks().unwrap();
    blocks.reverse();
    for (cid, data) in &blocks {
        let _ = g.admit(cid, data);
    }
    assert_eq!(
        b.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        final_name
    );

    // B's node is neither owner nor admin of A's bucket.
    let err = b.client.bucket_rename(&bucket, "hijack").await.unwrap_err();
    assert!(
        matches!(err, memvault_api::ApiError::Forbidden(_)),
        "got {err:?}"
    );
    assert_eq!(
        b.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        final_name
    );
}

/// A bucket whose only decls are legacy unsigned ones (bare `BucketDecl`
/// blocks written by older builds) still loads, before and after rebuild.
#[tokio::test]
async fn legacy_unsigned_decl_still_loads() {
    let a = TestNode::new();
    let bucket = BucketId::random();
    let decl = memvault_core::BucketDecl {
        bucket_id: bucket.clone(),
        name: "old-style".into(),
        description: None,
        owner_agent: None,
        owner_agent_pubkey: None,
        owner_node_pubkey: None,
        default_visibility: Visibility::Internal,
        default_classification: Classification::Internal,
        created_ns: 42,
        private_to_peer: None,
        role: BucketRole::Standard,
    };
    let bytes = serde_ipld_dagcbor::to_vec(&decl).unwrap();
    let cid = cid_from_bytes(&bytes).to_bytes();
    a.store
        .ingest_block(&cid, &bytes, &memvault_store::IngestMeta::default())
        .unwrap();
    assert_eq!(a.store.get_bucket(&bucket.0).unwrap(), Some(cid.clone()));
    assert_eq!(
        a.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        "old-style"
    );
    memvault_api::rebuild::rebuild_store(&a.client).unwrap();
    assert_eq!(
        a.client.bucket_get(&bucket).await.unwrap().unwrap().name,
        "old-style"
    );
}
