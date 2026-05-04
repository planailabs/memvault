//! Render an operation kind as a colored Pill.

use dioxus::prelude::*;
use plan_ai_design::{Pill, PillVariant};

#[component]
pub fn OpKindBadge(kind: String) -> Element {
    let variant = match kind.as_str() {
        "DocCreate" => PillVariant::Ok,
        "DocEdit" => PillVariant::Info,
        "AttachFile" => PillVariant::Accent,
        "EntityCreate" => PillVariant::Info,
        "EdgeAdd" => PillVariant::Info,
        "TagUpdate" => PillVariant::Muted,
        "Retract" => PillVariant::Bad,
        _ => PillVariant::Muted,
    };
    rsx! { Pill { variant, "{kind}" } }
}
