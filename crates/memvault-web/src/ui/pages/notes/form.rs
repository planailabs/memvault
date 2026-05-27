//! Note creation and edit form.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Button, ButtonVariant, Card, FormField};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateNoteResult {
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NoteFormData {
    title: String,
    body: String,
    tags: String,
    visibility: String,
}

#[server]
async fn create_note(
    body: String,
    title: String,
    tags_str: String,
    visibility: String,
    bucket_hex: Option<String>,
) -> Result<CreateNoteResult, ServerFnError> {
    use memvault_core::DocId;
    use memvault_doc::Document;
    use std::collections::BTreeMap;

    let client = crate::ui::state::client()?;
    let doc_id = DocId::random();

    let mut frontmatter = BTreeMap::new();
    if !title.is_empty() {
        frontmatter.insert("title".to_string(), serde_json::Value::String(title));
    }

    let doc = Document::new(doc_id.clone(), body, frontmatter);
    let tags = memvault_api::docs::parse_tags_csv(&tags_str);
    let vis = crate::api::docs::parse_visibility_str(Some(&visibility));
    client
        .put_doc(
            doc,
            tags,
            vis,
            bucket_hex
                .as_deref()
                .and_then(|h| {
                    let b = hex::decode(h).ok()?;
                    if b.len() != 32 {
                        return None;
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    Some(memvault_core::BucketId(a))
                })
                .as_ref(),
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(CreateNoteResult {
        id: hex::encode(doc_id.0),
    })
}

#[server]
async fn load_note_for_edit(id: String) -> Result<NoteFormData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id =
        crate::api::docs::parse_doc_id(&id).map_err(|e| ServerFnError::new(format!("{e}")))?;
    let doc = client
        .get_doc(&doc_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Document not found"))?;

    let title = doc
        .frontmatter
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(NoteFormData {
        title,
        body: doc.body,
        tags: String::new(),
        visibility: "internal".to_string(),
    })
}

#[server]
async fn update_note(id: String, body: String, title: String) -> Result<(), ServerFnError> {
    use memvault_doc::{TextOp, TextPatch};

    let client = crate::ui::state::client()?;
    let doc_id =
        crate::api::docs::parse_doc_id(&id).map_err(|e| ServerFnError::new(format!("{e}")))?;

    // Get current doc to compute a replace-all patch.
    let doc = client
        .get_doc(&doc_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Document not found"))?;

    let patch = TextPatch {
        ops: vec![TextOp::Delete(doc.body.len()), TextOp::Insert(body)],
    };
    client
        .edit_doc(&doc_id, patch)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update title in frontmatter.
    if !title.is_empty() {
        let mut fm = doc.frontmatter;
        fm.insert("title".to_string(), serde_json::Value::String(title));
        // SetMeta not directly exposed — title is stored on create only for now.
    }

    Ok(())
}

// ── Create form ────────────────────────────────────────────────────────

#[component]
pub fn NoteForm() -> Element {
    use_topbar(&t!("notes-new"));
    let navigator = use_navigator();

    let title = use_signal(String::new);
    let body = use_signal(String::new);
    let tags = use_signal(String::new);
    let visibility = use_signal(|| "internal".to_string());
    let mut saving = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let active_bucket = use_context::<crate::ui::topbar::ActiveBucketSignal>();
    let on_submit = move |e: Event<FormData>| {
        e.prevent_default();
        saving.set(true);
        error.set(None);
        let t = title.read().clone();
        let b = body.read().clone();
        let tg = tags.read().clone();
        let v = visibility.read().clone();
        let bkt = active_bucket.read().id.clone();
        spawn(async move {
            match create_note(b, t, tg, v, bkt).await {
                Ok(result) => {
                    navigator.push(Route::NoteDetail { id: result.id });
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                    saving.set(false);
                }
            }
        });
    };

    rsx! {
        NoteFormInner {
            page_title: t!("notes-new"),
            title, body, tags, visibility, saving, error,
            on_submit,
            cancel_route: Route::NoteList {},
        }
    }
}

// ── Edit form ──────────────────────────────────────────────────────────

#[component]
pub fn NoteEdit(id: String) -> Element {
    use_topbar(&t!("notes-edit"));
    let navigator = use_navigator();

    let edit_id = id.clone();
    let cancel_id = id.clone();

    let existing = use_server_future(move || {
        let id = id.clone();
        async move { load_note_for_edit(id).await }
    })?;

    let data = match &*existing.read() {
        Some(Ok(d)) => d.clone(),
        Some(Err(e)) => return rsx! { p { class: "text-danger", "Error: {e}" } },
        None => return rsx! { p { class: "text-fg-muted", {t!("loading")} } },
    };
    let title = use_signal(|| data.title.clone());
    let body = use_signal(|| data.body.clone());
    let tags = use_signal(|| data.tags.clone());
    let visibility = use_signal(|| data.visibility.clone());
    let mut saving = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let on_submit = move |e: Event<FormData>| {
        e.prevent_default();
        saving.set(true);
        error.set(None);
        let eid = edit_id.clone();
        let t = title.read().clone();
        let b = body.read().clone();
        spawn(async move {
            match update_note(eid.clone(), b, t).await {
                Ok(()) => {
                    navigator.push(Route::NoteDetail { id: eid });
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                    saving.set(false);
                }
            }
        });
    };

    rsx! {
        NoteFormInner {
            page_title: t!("notes-edit"),
            title, body, tags, visibility, saving, error,
            on_submit,
            cancel_route: Route::NoteDetail { id: cancel_id },
        }
    }
}

// ── Shared form inner ──────────────────────────────────────────────────

#[component]
fn NoteFormInner(
    page_title: String,
    mut title: Signal<String>,
    mut body: Signal<String>,
    mut tags: Signal<String>,
    mut visibility: Signal<String>,
    saving: Signal<bool>,
    error: Signal<Option<String>>,
    on_submit: EventHandler<Event<FormData>>,
    cancel_route: Route,
) -> Element {
    rsx! {
        div { class: "space-y-4 max-w-2xl",
            h2 { class: "h-page", "{page_title}" }

            if let Some(err) = &*error.read() {
                div { class: "alert alert-danger", "{err}" }
            }

            Card {
                form { class: "p-5 space-y-4", onsubmit: move |e| on_submit.call(e),
                    FormField { label: t!("notes-form-title"),
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: t!("notes-form-title-placeholder"),
                            value: "{title}",
                            oninput: move |e: Event<FormData>| title.set(e.value()),
                        }
                    }
                    FormField { label: t!("notes-form-body"),
                        textarea {
                            class: "input font-mono min-h-[300px]",
                            placeholder: t!("notes-form-body-placeholder"),
                            value: "{body}",
                            oninput: move |e: Event<FormData>| body.set(e.value()),
                        }
                    }
                    FormField { label: t!("notes-form-tags"),
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: t!("notes-form-tags-placeholder"),
                            value: "{tags}",
                            oninput: move |e: Event<FormData>| tags.set(e.value()),
                        }
                    }
                    FormField { label: t!("notes-form-visibility"),
                        select {
                            class: "input",
                            value: "{visibility}",
                            onchange: move |e: Event<FormData>| visibility.set(e.value()),
                            option { value: "internal", {t!("visibility-internal")} }
                            option { value: "federated", {t!("visibility-federated")} }
                            option { value: "public", {t!("visibility-public")} }
                        }
                    }
                    div { class: "flex gap-2 pt-2",
                        Button {
                            variant: ButtonVariant::Primary,
                            disabled: *saving.read(),
                            {t!("save")}
                        }
                        Link { to: cancel_route,
                            Button { variant: ButtonVariant::Secondary, {t!("cancel")} }
                        }
                    }
                }
            }
        }
    }
}
