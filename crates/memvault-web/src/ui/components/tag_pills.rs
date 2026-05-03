//! Render a list of (scope, label) tags as Pill chips.

use dioxus::prelude::*;
use plan_ai_design::{Pill, PillVariant};

#[component]
pub fn TagPills(tags: Vec<(String, String)>) -> Element {
    rsx! {
        div { class: "flex flex-wrap gap-1",
            for (scope, label) in &tags {
                Pill { variant: PillVariant::Muted, "{scope}:{label}" }
            }
        }
    }
}
