//! Render a visibility level as a colored Pill.

use dioxus::prelude::*;
use plan_ai_design::{Pill, PillVariant};

#[component]
pub fn VisibilityPill(visibility: String) -> Element {
    let variant = match visibility.as_str() {
        "internal" => PillVariant::Muted,
        "federated" => PillVariant::Info,
        "public" => PillVariant::Ok,
        _ => PillVariant::Muted,
    };
    rsx! { Pill { variant, "{visibility}" } }
}
