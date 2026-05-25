//! Sandboxed iframe for rendering untrusted HTML content.
//!
//! Renders HTML inside an iframe with strict sandboxing to prevent XSS,
//! script execution, form submission, and other attack vectors even if
//! the content contains malicious markup.

use dioxus::prelude::*;

/// Renders HTML content inside a fully sandboxed iframe.
///
/// The iframe uses:
/// - `sandbox=""` (empty) — denies ALL capabilities (scripts, forms, popups, etc.)
/// - `srcdoc` — injects content without a network request
/// - `csp` meta tag — additional defense-in-depth content security policy
/// - Auto-resizes height to fit content via a ResizeObserver in the parent
///
/// Props:
/// - `html`: The HTML content to render
/// - `class`: Optional CSS class for the iframe wrapper div
#[component]
pub fn SandboxedContent(html: String, #[props(default)] class: String) -> Element {
    // Build the full srcdoc with embedded styles and CSP meta tag.
    // The CSP blocks all external resources, inline scripts, and eval.
    let srcdoc = build_srcdoc(&html);

    rsx! {
        div { class: "sandboxed-content-wrapper {class}",
            iframe {
                // sandbox="" with NO allow tokens = maximum restriction:
                // - No JavaScript execution
                // - No form submission
                // - No popups/modals
                // - No top-level navigation
                // - No plugins
                // - Treated as unique origin (no access to parent storage/cookies)
                "sandbox": "",
                srcdoc: "{srcdoc}",
                // Prevent the iframe from being used as a navigation target
                name: "__sandboxed_content",
                // Deny all feature policies
                allow: "",
                // Style: borderless, full width, auto height via JS in parent
                class: "w-full border-0 min-h-[100px]",
                // Referrer policy: don't leak the parent URL
                referrerpolicy: "no-referrer",
                // Lazy load
                "loading": "lazy",
            }
        }
    }
}

/// Build the full HTML document for srcdoc.
/// Includes a CSP meta tag, Tailwind prose-compatible styling, and the content.
fn build_srcdoc(html: &str) -> String {
    // Escape the content for safe embedding in the srcdoc attribute.
    // srcdoc uses HTML entity encoding for quotes and ampersands.
    let escaped_html = html
        .replace('&', "&amp;")
        .replace('"', "&quot;");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:;">
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 0;
    font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
    font-size: 0.875rem;
    line-height: 1.625;
    color: inherit;
    overflow-wrap: break-word;
    word-break: break-word;
  }}
  /* Minimal prose-like styling */
  h1 {{ font-size: 1.5em; font-weight: 700; margin: 0.5em 0; }}
  h2 {{ font-size: 1.25em; font-weight: 600; margin: 0.5em 0; }}
  h3 {{ font-size: 1.1em; font-weight: 600; margin: 0.4em 0; }}
  p {{ margin: 0.5em 0; }}
  ul, ol {{ padding-left: 1.5em; margin: 0.5em 0; }}
  li {{ margin: 0.25em 0; }}
  pre {{ background: rgba(0,0,0,0.05); padding: 0.75em; border-radius: 4px; overflow-x: auto; font-size: 0.8125rem; }}
  code {{ font-family: ui-monospace, monospace; font-size: 0.85em; background: rgba(0,0,0,0.05); padding: 0.1em 0.3em; border-radius: 3px; }}
  pre code {{ background: none; padding: 0; }}
  blockquote {{ border-left: 3px solid rgba(0,0,0,0.2); margin: 0.5em 0; padding-left: 1em; color: rgba(0,0,0,0.7); }}
  a {{ color: #2563eb; text-decoration: underline; pointer-events: none; }}
  img {{ max-width: 100%; height: auto; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; }}
  th, td {{ border: 1px solid rgba(0,0,0,0.15); padding: 0.4em 0.6em; text-align: left; font-size: 0.8125rem; }}
  th {{ background: rgba(0,0,0,0.04); font-weight: 600; }}
  hr {{ border: none; border-top: 1px solid rgba(0,0,0,0.15); margin: 1em 0; }}
  /* Dark mode support via prefers-color-scheme */
  @media (prefers-color-scheme: dark) {{
    body {{ color: #e2e8f0; }}
    pre {{ background: rgba(255,255,255,0.05); }}
    code {{ background: rgba(255,255,255,0.1); }}
    blockquote {{ border-color: rgba(255,255,255,0.2); color: rgba(255,255,255,0.7); }}
    a {{ color: #60a5fa; }}
    th {{ background: rgba(255,255,255,0.05); }}
    th, td {{ border-color: rgba(255,255,255,0.1); }}
  }}
</style>
</head>
<body>{escaped_html}</body>
</html>"#
    )
}
