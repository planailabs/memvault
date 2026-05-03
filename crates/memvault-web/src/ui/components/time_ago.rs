//! Relative time display from nanosecond timestamps.

use dioxus::prelude::*;
use plan_ai_design::Mono;

/// Format a wall_ns timestamp as a relative time string.
fn format_time_ago(wall_ns: u64) -> String {
    if wall_ns == 0 {
        return "—".to_string();
    }
    let now_ns = now_nanos();
    if now_ns < wall_ns {
        return "just now".to_string();
    }
    let diff_secs = (now_ns - wall_ns) / 1_000_000_000;
    match diff_secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", diff_secs / 60),
        3600..=86399 => format!("{}h ago", diff_secs / 3600),
        86400..=2591999 => format!("{}d ago", diff_secs / 86400),
        _ => format!("{}w ago", diff_secs / 604800),
    }
}

/// Current time in nanoseconds since UNIX epoch, platform-aware.
fn now_nanos() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() * 1_000_000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[component]
pub fn TimeAgo(wall_ns: u64) -> Element {
    let display = format_time_ago(wall_ns);
    rsx! { Mono { "{display}" } }
}
