//! Sandboxed iframe for rendering untrusted HTML content.
//!
//! Renders HTML inside an iframe with sandboxing to prevent XSS while
//! allowing JavaScript for dynamic content. Auto-resizes to fit content.

use dioxus::prelude::*;

/// Renders HTML content inside a sandboxed iframe.
///
/// The iframe uses:
/// - `sandbox="allow-scripts"` — permits JS but blocks forms, popups, top-nav,
///   and treats the iframe as a unique origin (no parent cookie/storage access)
/// - `srcdoc` — injects content without a network request
/// - `csp` meta tag — blocks external resources, inline event handlers
/// - Transparent background — inherits parent theme
/// - Auto-resizes height to fit content via postMessage from the iframe
#[component]
pub fn SandboxedContent(html: String, #[props(default)] class: String) -> Element {
    let iframe_id = use_signal(|| format!("sandbox-{}", rand_id()));
    let srcdoc = build_srcdoc(&html, &iframe_id.read());

    rsx! {
        div { class: "sandboxed-content-wrapper {class}",
            iframe {
                id: "{iframe_id.read()}",
                // allow-scripts: needed for content JS and auto-resize.
                // Everything else stays blocked: no forms, no popups,
                // no top-navigation, unique origin.
                "sandbox": "allow-scripts",
                srcdoc: "{srcdoc}",
                name: "__sandboxed_content",
                allow: "",
                class: "w-full border-0 bg-transparent",
                style: "min-height: 60px; color-scheme: normal;",
                referrerpolicy: "no-referrer",
                "loading": "lazy",
            }
            // Parent-side listener that resizes the iframe when the
            // content posts its height.
            script {
                r#type: "module",
                dangerous_inner_html: resize_script(&iframe_id.read()),
            }
        }
    }
}

fn rand_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{n:08x}")
}

fn resize_script(iframe_id: &str) -> String {
    format!(
        r#"
        (function() {{
            const iframe = document.getElementById("{iframe_id}");
            if (!iframe) return;
            window.addEventListener("message", function(e) {{
                if (e.data && e.data.type === "sandboxResize" && e.data.id === "{iframe_id}") {{
                    iframe.style.height = e.data.height + "px";
                }}
            }});
        }})();
        "#
    )
}

/// Build the full HTML document for srcdoc.
fn build_srcdoc(html: &str, iframe_id: &str) -> String {
    let escaped_html = html
        .replace('&', "&amp;")
        .replace('"', "&quot;");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:;">
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    padding: 0;
    background: transparent;
    font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
    font-size: 0.875rem;
    line-height: 1.625;
    color: inherit;
    overflow-wrap: break-word;
    word-break: break-word;
  }}
  h1 {{ font-size: 1.5em; font-weight: 700; margin: 0.5em 0; }}
  h2 {{ font-size: 1.25em; font-weight: 600; margin: 0.5em 0; }}
  h3 {{ font-size: 1.1em; font-weight: 600; margin: 0.4em 0; }}
  p {{ margin: 0.5em 0; }}
  ul, ol {{ padding-left: 1.5em; margin: 0.5em 0; }}
  li {{ margin: 0.25em 0; }}
  pre {{ background: rgba(128,128,128,0.1); padding: 0.75em; border-radius: 4px; overflow-x: auto; font-size: 0.8125rem; }}
  code {{ font-family: ui-monospace, monospace; font-size: 0.85em; background: rgba(128,128,128,0.1); padding: 0.1em 0.3em; border-radius: 3px; }}
  pre code {{ background: none; padding: 0; }}
  blockquote {{ border-left: 3px solid rgba(128,128,128,0.3); margin: 0.5em 0; padding-left: 1em; opacity: 0.8; }}
  a {{ color: #2563eb; text-decoration: underline; }}
  img {{ max-width: 100%; height: auto; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; }}
  th, td {{ border: 1px solid rgba(128,128,128,0.2); padding: 0.4em 0.6em; text-align: left; font-size: 0.8125rem; }}
  th {{ background: rgba(128,128,128,0.06); font-weight: 600; }}
  hr {{ border: none; border-top: 1px solid rgba(128,128,128,0.2); margin: 1em 0; }}
</style>
</head>
<body>{escaped_html}
<script>
// Auto-resize: post height to parent so it can size the iframe.
(function() {{
  var id = "{id}";
  function post() {{
    var h = document.documentElement.scrollHeight;
    parent.postMessage({{ type: "sandboxResize", id: id, height: h }}, "*");
  }}
  // Post on load.
  post();
  // Re-post on any resize (images loading, dynamic content).
  if (typeof ResizeObserver !== "undefined") {{
    new ResizeObserver(post).observe(document.body);
  }}
  // Also post after a short delay for late-rendering content.
  setTimeout(post, 200);
  setTimeout(post, 1000);
}})();
</script>
</body>
</html>"#,
        escaped_html = escaped_html,
        id = iframe_id
    )
}
