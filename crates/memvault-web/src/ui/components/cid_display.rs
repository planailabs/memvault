//! Truncated CID display with monospace styling.

use dioxus::prelude::*;
use plan_ai_design::Mono;

#[component]
pub fn CidDisplay(cid: String, len: Option<usize>) -> Element {
    let len = len.unwrap_or(12);
    let display = if cid.len() > len {
        format!("{}...", &cid[..len])
    } else {
        cid.clone()
    };
    rsx! {
        span { title: "{cid}",
            Mono { "{display}" }
        }
    }
}
