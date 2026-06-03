//! Skill bundle hydration — materialize a skill's components onto disk.
//!
//! memvault is the trusted registry; it does not execute skills. Hydration is
//! the one step that puts a bundle on the local filesystem so an agent can run
//! its scripts with its own tooling. This is a shared helper over the
//! `MemvaultClient` trait (it reuses `skill_get` + the block-read methods) —
//! NOT a trait method, because materializing to the *caller's* disk can't
//! thread through to a remote server.
//!
//! ## Trust
//!
//! Materializing executable resources writes runnable code to disk, so it is
//! the natural trust boundary. Callers should only hydrate skills they trust
//! (granted bucket + attested author). Full sigchain-author verification at
//! this layer is a follow-up; until then `set_executable` lets a caller opt
//! out of the executable bit entirely (the default), so an untrusted bundle
//! never lands as directly-runnable code without an explicit decision.
//!
//! ## Safety
//!
//! Resource paths come from edge props (untrusted), so each is validated to be
//! relative and free of `..` / root components before it is joined to `dest` —
//! a bundle can never write outside its own directory.

use std::path::{Component, Path, PathBuf};

use memvault_core::{EntityId, NodeRef};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};

/// What a hydration produced.
#[derive(Debug, Clone, Default)]
pub struct HydrateReport {
    pub dest: PathBuf,
    /// Relative paths written, in order.
    pub written: Vec<String>,
    /// Components skipped (with a reason), e.g. an unresolved node or an
    /// executable resource when `set_executable` was false.
    pub skipped: Vec<String>,
}

/// Validate an untrusted relative path and join it under `dest`. Rejects
/// absolute paths and any `..` / root / prefix component (path traversal).
fn safe_join(dest: &Path, rel: &str) -> Result<PathBuf> {
    let candidate = Path::new(rel);
    for comp in candidate.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(ApiError::Other(format!(
                    "unsafe bundle path {rel:?}: only relative paths without '..' are allowed"
                )));
            }
        }
    }
    Ok(dest.join(candidate))
}

fn write_file(dest: &Path, rel: &str, bytes: &[u8], executable: bool) -> Result<()> {
    let path = safe_join(dest, rel)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ApiError::Other(format!("create {parent:?}: {e}")))?;
    }
    std::fs::write(&path, bytes).map_err(|e| ApiError::Other(format!("write {path:?}: {e}")))?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| ApiError::Other(format!("stat {path:?}: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| ApiError::Other(format!("chmod {path:?}: {e}")))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}

/// Materialize a skill bundle into `dest`. Instruction docs land as
/// `SKILL.md` (or their edge `path`, or `SKILL.<n>.md` when there are
/// several); resources land at their edge `path`. When `set_executable` is
/// false, resources flagged executable are still written but without the
/// executable bit (and noted in the report's `skipped`).
pub async fn hydrate_skill(
    client: &dyn MemvaultClient,
    skill_id: &EntityId,
    dest: &Path,
    set_executable: bool,
) -> Result<HydrateReport> {
    let bundle = client
        .skill_get(skill_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("skill {}", hex::encode(skill_id.0))))?;

    std::fs::create_dir_all(dest)
        .map_err(|e| ApiError::Other(format!("create {dest:?}: {e}")))?;

    let mut report = HydrateReport {
        dest: dest.to_path_buf(),
        ..Default::default()
    };

    let single_instruction = bundle.instructions.len() == 1;
    for (i, instr) in bundle.instructions.iter().enumerate() {
        let rel = if let Some(p) = instr.path.as_deref().filter(|p| !p.is_empty()) {
            p.to_string()
        } else if single_instruction {
            "SKILL.md".to_string()
        } else {
            format!("SKILL.{i}.md")
        };
        match NodeRef::from_tag_label(&instr.node) {
            Some(NodeRef::Doc(doc_id)) => match client.get_doc(&doc_id).await? {
                Some(doc) => {
                    write_file(dest, &rel, doc.body.as_bytes(), false)?;
                    report.written.push(rel);
                }
                None => report.skipped.push(format!("{} (doc missing)", instr.node)),
            },
            _ => report
                .skipped
                .push(format!("{} (instruction not a doc)", instr.node)),
        }
    }

    for res in &bundle.resources {
        let Some(rel) = res.path.as_deref().filter(|p| !p.is_empty()) else {
            report
                .skipped
                .push(format!("{} (no bundle path)", res.node));
            continue;
        };
        let want_exec = res.executable && set_executable;
        if res.executable && !set_executable {
            report
                .skipped
                .push(format!("{rel} (executable bit withheld)"));
        }
        match NodeRef::from_tag_label(&res.node) {
            Some(NodeRef::Attachment(cid)) => {
                let data = client.read_file(&cid).await?;
                write_file(dest, rel, &data, want_exec)?;
                report.written.push(rel.to_string());
            }
            Some(NodeRef::Doc(doc_id)) => match client.get_doc(&doc_id).await? {
                Some(doc) => {
                    write_file(dest, rel, doc.body.as_bytes(), want_exec)?;
                    report.written.push(rel.to_string());
                }
                None => report.skipped.push(format!("{} (doc missing)", res.node)),
            },
            _ => report
                .skipped
                .push(format!("{} (entity resource not materialized)", res.node)),
        }
    }

    Ok(report)
}
