//! Note creation form.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, FormField};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateNoteResult {
    id: String,
}

#[server]
async fn create_note(
    body: String,
    title: String,
    tags_str: String,
    visibility: String,
) -> Result<CreateNoteResult, ServerFnError> {
    use memvault_core::DocId;
    use memvault_doc::Document;
    use std::collections::BTreeMap;

    let client = crate::ui::state::client()?;
    let doc_id = DocId::random();

    let mut frontmatter = BTreeMap::new();
    if !title.is_empty() {
        frontmatter.insert(
            "title".to_string(),
            serde_json::Value::String(title),
        );
    }

    let doc = Document::new(doc_id.clone(), body, frontmatter);

    let tags: Vec<(String, String)> = tags_str
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let s = s.trim();
            let mut parts = s.splitn(2, ':');
            let scope = parts.next().unwrap_or("").to_string();
            let label = parts.next().unwrap_or("").to_string();
            (scope, label)
        })
        .collect();

    let vis = crate::api::docs::parse_visibility_str(Some(&visibility));
    client
        .put_doc(doc, tags, vis)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(CreateNoteResult {
        id: hex::encode(doc_id.0),
    })
}

#[component]
pub fn NoteForm() -> Element {
    use_topbar("New Note");
    let navigator = use_navigator();

    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut tags = use_signal(String::new);
    let mut visibility = use_signal(|| "internal".to_string());
    let mut saving = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let on_submit = move |_: Event<FormData>| {
        saving.set(true);
        error.set(None);
        let t = title.read().clone();
        let b = body.read().clone();
        let tg = tags.read().clone();
        let v = visibility.read().clone();
        spawn(async move {
            match create_note(b, t, tg, v).await {
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
        div { class: "space-y-4 max-w-2xl",
            h2 { class: "h-page", "New Note" }

            if let Some(err) = &*error.read() {
                div { class: "alert alert-danger", "{err}" }
            }

            Card {
                form { class: "p-5 space-y-4", onsubmit: on_submit,
                    FormField { label: "Title".to_string(),
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Note title",
                            value: "{title}",
                            oninput: move |e: Event<FormData>| title.set(e.value()),
                        }
                    }
                    FormField { label: "Body".to_string(),
                        textarea {
                            class: "input font-mono min-h-[300px]",
                            placeholder: "Markdown content...",
                            value: "{body}",
                            oninput: move |e: Event<FormData>| body.set(e.value()),
                        }
                    }
                    FormField { label: "Tags".to_string(),
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "scope:label, scope:label, ...",
                            value: "{tags}",
                            oninput: move |e: Event<FormData>| tags.set(e.value()),
                        }
                    }
                    FormField { label: "Visibility".to_string(),
                        select {
                            class: "input",
                            value: "{visibility}",
                            onchange: move |e: Event<FormData>| visibility.set(e.value()),
                            option { value: "internal", "Internal" }
                            option { value: "federated", "Federated" }
                            option { value: "public", "Public" }
                        }
                    }
                    div { class: "flex gap-2 pt-2",
                        Button {
                            variant: ButtonVariant::Primary,
                            disabled: *saving.read(),
                            "Save"
                        }
                        Link { to: Route::NoteList {},
                            Button { variant: ButtonVariant::Secondary, "Cancel" }
                        }
                    }
                }
            }
        }
    }
}
