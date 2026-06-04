//! Route enum and top-level App component.

use dioxus::prelude::*;
use dioxus_i18n::prelude::*;
use unic_langid::langid;

use super::layout::Layout;
use super::pages::admin::dashboard::AdminDashboard;
use super::pages::admin::tokens::TokenManagement;
use super::pages::admin::trust::TrustTreePage;
use super::pages::audit::AuditLog;
use super::pages::buckets::detail::BucketDetail;
use super::pages::buckets::list::BucketList;
use super::pages::files::detail::FileDetail;
use super::pages::files::explorer::FileExplorer;
use super::pages::graph::detail::EntityDetail;
use super::pages::graph::explorer::GraphExplorer;
use super::pages::graph::history::EntityHistory;
use super::pages::notes::detail::NoteDetail;
use super::pages::notes::form::{NoteEdit, NoteForm};
use super::pages::notes::history::NoteHistory;
use super::pages::notes::list::NoteList;
use super::pages::skills::detail::SkillDetail;
use super::pages::skills::list::SkillList;
use super::pages::vfs::explorer::VfsExplorer;
use super::pages::views::ViewManager;

#[derive(Debug, Clone, Routable, PartialEq)]
pub enum Route {
    #[layout(Layout)]
    #[route("/")]
    NoteList {},
    #[route("/notes/new")]
    NoteForm {},
    #[route("/notes/:id/edit")]
    NoteEdit { id: String },
    #[route("/notes/:id")]
    NoteDetail { id: String },
    #[route("/notes/:id/history")]
    NoteHistory { id: String },
    #[route("/graph")]
    GraphExplorer {},
    #[route("/graph/:id")]
    EntityDetail { id: String },
    #[route("/graph/:id/history")]
    EntityHistory { id: String },
    #[route("/files")]
    FileExplorer {},
    #[route("/files/:cid")]
    FileDetail { cid: String },
    #[route("/vfs")]
    VfsExplorer {},
    #[route("/views")]
    ViewManager {},
    #[route("/buckets")]
    BucketList {},
    #[route("/buckets/:id")]
    BucketDetail { id: String },
    #[route("/skills")]
    SkillList {},
    #[route("/skills/:id")]
    SkillDetail { id: String },
    #[route("/audit")]
    AuditLog {},
    #[route("/admin")]
    AdminDashboard {},
    #[route("/admin/tokens")]
    TokenManagement {},
    #[route("/admin/trust")]
    TrustTreePage {},
}

use plan_ai_design::theme_toggle::{THEME_INIT_SCRIPT, WASM_LOADING_INNER, WASM_LOADING_STYLE};

#[allow(non_snake_case)]
pub fn App() -> Element {
    let mut i18n = use_init_i18n(|| {
        let en: &'static str = Box::leak(
            format!(
                "{}\n{}",
                plan_ai_design::i18n::EN_US,
                include_str!("./en-US.ftl")
            )
            .into_boxed_str(),
        );
        let de: &'static str = Box::leak(
            format!(
                "{}\n{}",
                plan_ai_design::i18n::DE_DE,
                include_str!("./de-DE.ftl")
            )
            .into_boxed_str(),
        );
        I18nConfig::new(langid!("en-US"))
            .with_locale(Locale::new_static(langid!("en-US"), en))
            .with_locale(Locale::new_static(langid!("de-DE"), de))
    });

    // Restore language preference from localStorage on first load.
    use_effect(move || {
        spawn(async move {
            let result = document::eval(
                "try { return localStorage.getItem('lang') || ''; } catch(e) { return ''; }",
            )
            .await;
            if let Ok(val) = result {
                if let Some(lang) = val.as_str() {
                    if lang == "de-DE" {
                        let _ = i18n.set_language(langid!("de-DE"));
                    }
                }
            }
        });
    });

    // Drop the pre-hydration loading banner once WASM has hydrated. Gated on a
    // signal (not a one-shot JS `.remove()`) so Dioxus owns the node: a later
    // suspense-driven re-render — e.g. a page restarting a `use_server_future` —
    // can't resurrect a node we deleted behind Dioxus's back.
    let mut hydrated = use_signal(|| false);
    use_effect(move || hydrated.set(true));

    rsx! {
        script { dangerous_inner_html: THEME_INIT_SCRIPT }
        document::Stylesheet { href: asset!("/public/tailwind.css") }

        if !hydrated() {
            div { id: "wasm-loading",
                style: WASM_LOADING_STYLE,
                dangerous_inner_html: WASM_LOADING_INNER,
            }
        }

        Router::<Route> {}
    }
}
