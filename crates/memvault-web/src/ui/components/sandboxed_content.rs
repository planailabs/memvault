//! Sandboxed iframe for rendering untrusted HTML content.
//!
//! Renders HTML inside an iframe with sandboxing to prevent XSS while
//! allowing JavaScript for dynamic content. Auto-resizes to fit content.
//! Inherits the parent page's stylesheets and dark/light theme.

use dioxus::prelude::*;

/// Renders HTML content inside a sandboxed iframe.
///
/// Features:
/// - `sandbox="allow-scripts"` — JS for resize/theme, no forms/popups/nav
/// - Inherits parent stylesheets via postMessage injection
/// - Syncs dark/light/auto theme from parent via postMessage
/// - Transparent background — inherits parent theme colors
/// - Auto-resizes height to fit content
#[component]
pub fn SandboxedContent(html: String, #[props(default)] class: String) -> Element {
    let iframe_id = use_signal(|| format!("sandbox-{}", rand_id()));
    let srcdoc = build_srcdoc(&html, &iframe_id.read());

    rsx! {
        div { class: "sandboxed-content-wrapper {class}",
            iframe {
                id: "{iframe_id.read()}",
                "sandbox": "allow-scripts",
                srcdoc: "{srcdoc}",
                name: "__sandboxed_content",
                allow: "",
                class: "w-full border-0 bg-transparent",
                style: "min-height: 60px; color-scheme: normal;",
                referrerpolicy: "no-referrer",
                "loading": "lazy",
            }
            script {
                r#type: "module",
                dangerous_inner_html: parent_script(&iframe_id.read()),
            }
        }
    }
}

fn rand_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{n:08x}")
}

/// Parent-side script: handles resize messages AND pushes stylesheets + theme
/// into the iframe once it's loaded.
fn parent_script(iframe_id: &str) -> String {
    format!(
        r#"
(function() {{
  const iframe = document.getElementById("{iframe_id}");
  if (!iframe) return;

  // Allowed in-app paths a sandboxed iframe is permitted to ask the
  // parent to navigate to. Same-origin only, relative paths only,
  // and the leading segment must be one of these. Anything else is
  // silently dropped — a hostile or malformed body must not be able to
  // drive the parent off-route.
  function isAllowedNav(href) {{
    if (typeof href !== "string" || href.length > 2048) return false;
    if (!href.startsWith("/")) return false;        // no absolute URLs
    if (href.startsWith("//")) return false;        // no protocol-relative
    // Parse against the current origin and verify it stays same-origin.
    var url;
    try {{ url = new URL(href, window.location.origin); }} catch (_) {{ return false; }}
    if (url.origin !== window.location.origin) return false;
    var p = url.pathname;
    // Explicit allowlist; tightens as new in-app routes appear.
    var hexId = /^[0-9a-f]+$/i;
    if (p.startsWith("/notes/")) return hexId.test(p.slice(7));
    if (p.startsWith("/graph/")) return hexId.test(p.slice(7));
    if (p.startsWith("/files/")) return hexId.test(p.slice(7));
    if (p === "/search") return true;
    return false;
  }}

  // Handle resize + navigation messages from this iframe (id match
  // gates messages from other sandboxed iframes on the same page).
  window.addEventListener("message", function(e) {{
    if (!e.data || e.data.id !== "{iframe_id}") return;
    if (e.data.type === "sandboxResize") {{
      iframe.style.height = e.data.height + "px";
    }} else if (e.data.type === "sandboxNav") {{
      if (isAllowedNav(e.data.href)) {{
        // Plain assignment lets the SPA router pick up the new path
        // and avoids granting the iframe `allow-top-navigation`.
        window.location.assign(e.data.href);
      }} else {{
        console.warn("blocked sandboxed nav:", e.data.href);
      }}
    }}
  }});

  // Collect parent stylesheets and current theme, push to iframe.
  function pushTheme() {{
    if (!iframe.contentWindow) return;
    var sheets = [];
    document.querySelectorAll('link[rel="stylesheet"]').forEach(function(l) {{
      if (l.href) sheets.push(l.href);
    }});
    // Detect theme: check html data-theme, class, or prefers-color-scheme.
    var html = document.documentElement;
    var theme = html.getAttribute("data-theme")
      || (html.classList.contains("dark") ? "dark" : "")
      || (html.classList.contains("light") ? "light" : "");
    if (!theme) {{
      theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }}
    iframe.contentWindow.postMessage({{
      type: "themeSync",
      stylesheets: sheets,
      theme: theme,
      classes: html.className
    }}, "*");
  }}

  // Push after iframe loads.
  iframe.addEventListener("load", function() {{
    setTimeout(pushTheme, 50);
  }});
  // Also push immediately in case it's already loaded.
  setTimeout(pushTheme, 100);

  // Re-push when parent theme changes.
  var observer = new MutationObserver(function() {{ pushTheme(); }});
  observer.observe(document.documentElement, {{ attributes: true, attributeFilter: ["class", "data-theme"] }});
  // Also watch prefers-color-scheme.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", pushTheme);
}})();
"#
    )
}

/// Build the full HTML document for srcdoc. Dioxus's `srcdoc: "{var}"`
/// interpolation does its own HTML-attribute escaping (`&` → `&amp;`,
/// `"` → `&quot;`), so we pass raw HTML and let it handle the encoding.
/// Manually pre-escaping here causes double-encoding — `<a href="/x">`
/// goes out as `<a href=&amp;quot;/x&amp;quot;>`, the browser decodes
/// once to `&quot;`, and HTML parses it as an unquoted attribute that
/// includes literal quote characters as part of the URL.
fn build_srcdoc(html: &str, iframe_id: &str) -> String {
    // Passed RAW (unescaped) on purpose — Dioxus attribute-escapes the whole
    // `srcdoc` once (see the doc comment above). Do NOT add escaping here.
    let raw_html = html;

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' * 'self'; img-src data: blob:; font-src data: *;">
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    padding: 0;
    background: transparent;
    overflow: visible;
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
<body><div class="card"><div class="p-5 prose prose-sm dark:prose-invert max-w-none">{raw_html}</div></div>
<script>
(function() {{
  var id = "{id}";
  var stylesInjected = false;

  var lastH = 0;
  function postHeight() {{
    // Use the maximum of multiple measurements to avoid clipping.
    var h = Math.max(
      document.documentElement.scrollHeight,
      document.documentElement.offsetHeight,
      document.body.scrollHeight,
      document.body.offsetHeight
    );
    if (h !== lastH) {{
      lastH = h;
      parent.postMessage({{ type: "sandboxResize", id: id, height: h }}, "*");
    }}
  }}

  // ResizeObserver on <html> catches all layout changes: content,
  // stylesheets loading, images, font swap, theme change.
  if (typeof ResizeObserver !== "undefined") {{
    new ResizeObserver(postHeight).observe(document.documentElement);
  }}
  // MutationObserver catches DOM changes that may not trigger resize
  // (e.g. class/attribute changes from theme sync).
  new MutationObserver(postHeight).observe(document.body, {{
    childList: true, subtree: true, attributes: true
  }});
  // Initial post.
  postHeight();

  // Intercept link clicks inside the sandbox and ask the parent to
  // navigate. The iframe is `sandbox=allow-scripts` (no
  // `allow-top-navigation`), so anchor clicks otherwise do nothing
  // useful — without this they either silently fail or get blocked by
  // the browser. By forwarding the href as a postMessage we keep the
  // parent in charge of routing AND let the parent validate the
  // target before it commits.
  document.addEventListener("click", function(e) {{
    var el = e.target;
    while (el && el.nodeName !== "A") el = el.parentElement;
    if (!el) return;
    var href = el.getAttribute("href");
    if (!href) return;
    // Defensive: refuse javascript:/data:/vbscript: schemes outright.
    var lower = href.trim().toLowerCase();
    if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("vbscript:")) {{
      e.preventDefault();
      return;
    }}
    // Forward in-app relative links; external (http/https) ones are
    // left to default behavior (likely no-op under the sandbox).
    if (href.startsWith("/") && !href.startsWith("//")) {{
      e.preventDefault();
      parent.postMessage({{ type: "sandboxNav", id: id, href: href }}, "*");
    }}
  }}, true);

  // Listen for theme sync from parent.
  window.addEventListener("message", function(e) {{
    if (!e.data || e.data.type !== "themeSync") return;

    // Inject parent stylesheets (once). Listen for each load event
    // to re-measure (no timers needed).
    if (!stylesInjected && e.data.stylesheets) {{
      var pending = e.data.stylesheets.length;
      e.data.stylesheets.forEach(function(href) {{
        var link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = href;
        link.onload = link.onerror = function() {{
          pending--;
          postHeight();
        }};
        document.head.appendChild(link);
      }});
      stylesInjected = true;
    }}

    // Apply theme classes and data-theme.
    if (e.data.theme) {{
      document.documentElement.setAttribute("data-theme", e.data.theme);
    }}
    if (typeof e.data.classes === "string") {{
      document.documentElement.className = e.data.classes;
    }}
    postHeight();
  }});
}})();
</script>
</body>
</html>"#,
        raw_html = raw_html,
        id = iframe_id
    )
}
