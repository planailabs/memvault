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
use super::pages::timeline::Timeline;
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
    #[route("/timeline")]
    Timeline {},
    #[route("/views")]
    ViewManager {},
    #[route("/audit")]
    AuditLog {},
    #[route("/admin")]
    AdminDashboard {},
    #[route("/admin/tokens")]
    TokenManagement {},
}

#[allow(non_snake_case)]
pub fn App() -> Element {
    use_init_i18n(|| {
        I18nConfig::new(langid!("en-US"))
            .with_locale(Locale::new_static(
                langid!("en-US"),
                plan_ai_design::i18n::EN_US,
            ))
    });

    rsx! {
        Router::<Route> {}
    }
}
