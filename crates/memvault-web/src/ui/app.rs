//! Route enum and top-level App component.

use dioxus::prelude::*;
use dioxus_i18n::prelude::*;
use unic_langid::langid;

use super::layout::Layout;
use super::pages::admin::dashboard::AdminDashboard;
use super::pages::admin::tokens::TokenManagement;
use super::pages::audit::AuditLog;
use super::pages::files::detail::FileDetail;
use super::pages::files::explorer::FileExplorer;
use super::pages::graph::detail::EntityDetail;
use super::pages::graph::explorer::GraphExplorer;
use super::pages::graph::history::EntityHistory;
use super::pages::notes::detail::NoteDetail;
use super::pages::notes::form::{NoteEdit, NoteForm};
use super::pages::notes::history::NoteHistory;
use super::pages::notes::list::NoteList;
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
    #[route("/audit")]
    AuditLog {},
    #[route("/admin")]
    AdminDashboard {},
    #[route("/admin/tokens")]
    TokenManagement {},
}

// Sets `.dark` class on `<html>` before CSS loads, preventing theme flash.
const THEME_INIT_SCRIPT: &str = r#"
(function(){
    try {
        var d = document.documentElement;
        var t = localStorage.getItem('theme');
        var dark = t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches);
        d.classList.toggle('dark', dark);
        d.style.colorScheme = dark ? 'dark' : 'light';
    } catch(e){}
})();
"#;

// Pre-hydration loading banner with self-contained styling.
const WASM_LOADING_INNER: &str = r#"<style>@media(prefers-color-scheme:dark){#wasm-loading{background:#1a1f2e!important;color:#7b9fe0!important;border-bottom-color:#2a3040!important}}#wasm-loading svg{animation:wasm-spin 1s linear infinite;width:16px;height:16px}@keyframes wasm-spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style><svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" opacity="0.25"/><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" opacity="0.75"/></svg>Loading&hellip;"#;

#[allow(non_snake_case)]
pub fn App() -> Element {
    let mut i18n = use_init_i18n(|| {
        let en: &'static str = Box::leak(
            format!("{}\n{}", plan_ai_design::i18n::EN_US, include_str!("./en-US.ftl")).into_boxed_str(),
        );
        let de: &'static str = Box::leak(
            format!("{}\n{}", plan_ai_design::i18n::DE_DE, include_str!("./de-DE.ftl")).into_boxed_str(),
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

    // Remove pre-hydration loading banner once WASM has hydrated.
    use_effect(|| {
        document::eval("document.getElementById('wasm-loading')?.remove();");
    });

    rsx! {
        script { dangerous_inner_html: THEME_INIT_SCRIPT }

        div { id: "wasm-loading",
            style: "position:fixed;top:0;left:0;right:0;display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;background:#f0f4ff;color:#3b5998;font-family:system-ui,-apple-system,sans-serif;font-size:13px;z-index:9999;border-bottom:1px solid #d0d8e8",
            dangerous_inner_html: WASM_LOADING_INNER,
        }

        Router::<Route> {}
    }
}
