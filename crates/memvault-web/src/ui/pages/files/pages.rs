//! Page viewer — pre-rendered page images with a PDF.js-style selectable
//! text layer (transparent, absolutely positioned word spans over the
//! image, so browser-native selection/copy/find work).

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::Card;
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

const MIN_ZOOM: f64 = 0.25;
const MAX_ZOOM: f64 = 4.0;
const ZOOM_STEP: f64 = 1.25;

/// Text-layer CSS (PDF.js approach): spans carry the words invisibly so
/// selection highlights and copies real text while the raster shows through.
const TEXTLAYER_CSS: &str = "\
.mv-textlayer { user-select: text; }\n\
.mv-textlayer span { color: transparent; white-space: pre; cursor: text; user-select: text; }\n\
.mv-textlayer span::selection { background: rgba(59,130,246,.4); color: transparent; }";

// ── Local DTOs (memvault-api types don't compile to wasm) ───────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PageManifestView {
    /// Wire status string: pending | done | failed | unavailable | unsupported.
    status: String,
    page_count: u32,
    /// (page_no, width, height) in image pixels; page_no is 1-based.
    pages: Vec<(u32, u32, u32)>,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TextLayerView {
    /// Image pixel dims the word coords are relative to.
    width: u32,
    height: u32,
    /// (text, x, y, w, h) in image pixel coordinates.
    words: Vec<(String, f32, f32, f32, f32)>,
}

#[server]
async fn get_page_manifest(cid: String) -> Result<PageManifestView, ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID hex"))?;
    let info = client
        .read_page_render(&cid_bytes)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(PageManifestView {
        status: serde_json::to_value(info.status)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unavailable".into()),
        page_count: info.page_count,
        pages: info
            .pages
            .into_iter()
            .map(|p| (p.page_no, p.width, p.height))
            .collect(),
        error: info.error,
    })
}

#[server]
async fn get_page_text_layer(
    cid: String,
    page_no: u32,
) -> Result<Option<TextLayerView>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID hex"))?;
    let layer = client
        .read_page_text_layer(&cid_bytes, page_no)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(layer.map(|l| TextLayerView {
        width: l.width,
        height: l.height,
        words: l
            .words
            .into_iter()
            .map(|w| (w.text, w.x, w.y, w.w, w.h))
            .collect(),
    }))
}

#[component]
pub fn FilePages(cid: String) -> Element {
    use_topbar(&t!("pages-title"));

    let mut manifest = use_signal(|| None::<PageManifestView>);
    let mut zoom = use_signal(|| 1.0f64);
    let mut current_page = use_signal(|| 1u32);

    // Poll the render manifest every 2s until it leaves "pending" —
    // reading it lazily triggers rendering. Dioxus cancels the task on
    // navigation.
    let poll_cid = cid.clone();
    use_effect(move || {
        let cid = poll_cid.clone();
        spawn(async move {
            loop {
                match get_page_manifest(cid.clone()).await {
                    Ok(m) => {
                        let pending = m.status == "pending";
                        manifest.set(Some(m));
                        if !pending {
                            break;
                        }
                    }
                    Err(_) => break,
                }
                super::media_poll_delay().await;
            }
        });
    });

    let m = manifest.read().clone();
    let status = m
        .as_ref()
        .map(|x| x.status.clone())
        .unwrap_or_else(|| "pending".into());
    let pages_list = m.as_ref().map(|x| x.pages.clone()).unwrap_or_default();
    let page_count = m
        .as_ref()
        .map(|x| x.page_count.max(x.pages.len() as u32))
        .unwrap_or(0);
    let error_text = m
        .as_ref()
        .and_then(|x| x.error.clone())
        .unwrap_or_else(|| "unknown".into());
    let zoom_val = *zoom.read();
    let cur = *current_page.read();

    // Scroll a page into view and remember it as the current one.
    let mut goto_page = move |p: u32| {
        current_page.set(p);
        document::eval(&format!(
            "var el = document.getElementById('page-{p}'); \
             if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});"
        ));
    };

    let fit_width = move |_| {
        let max_w = manifest
            .peek()
            .as_ref()
            .map(|m| m.pages.iter().map(|p| p.1).max().unwrap_or(0))
            .unwrap_or(0);
        spawn(async move {
            let result = document::eval(
                "var el = document.getElementById('mv-pages-scroll'); \
                 return el ? el.clientWidth : 0;",
            )
            .await;
            if let Ok(v) = result
                && let Some(w) = v.as_f64()
                && w > 0.0
                && max_w > 0
            {
                // Leave room for the container padding (p-6 → 24px per side).
                zoom.set(((w - 48.0) / max_w as f64).clamp(MIN_ZOOM, MAX_ZOOM));
            }
        });
    };

    rsx! {
        style { dangerous_inner_html: TEXTLAYER_CSS }
        div { class: "flex flex-col h-full min-h-0 gap-3",
            // ── Toolbar ─────────────────────────────────────────────
            div { class: "flex flex-wrap items-center gap-2",
                Link {
                    to: Route::FileDetail { cid: cid.clone() },
                    class: "btn btn-sm btn-secondary",
                    {t!("pages-back")}
                }
                div { class: "flex-1" }
                if !pages_list.is_empty() {
                    button {
                        class: "btn btn-sm btn-secondary font-mono",
                        title: t!("pages-zoom-out"),
                        onclick: move |_| {
                            let z = (*zoom.peek() / ZOOM_STEP).clamp(MIN_ZOOM, MAX_ZOOM);
                            zoom.set(z);
                        },
                        "−"
                    }
                    button {
                        class: "btn btn-sm btn-secondary font-mono",
                        title: t!("pages-zoom-reset"),
                        onclick: move |_| zoom.set(1.0),
                        {format!("{:.0}%", zoom_val * 100.0)}
                    }
                    button {
                        class: "btn btn-sm btn-secondary font-mono",
                        title: t!("pages-zoom-in"),
                        onclick: move |_| {
                            let z = (*zoom.peek() * ZOOM_STEP).clamp(MIN_ZOOM, MAX_ZOOM);
                            zoom.set(z);
                        },
                        "+"
                    }
                    button {
                        class: "btn btn-sm btn-secondary",
                        onclick: fit_width,
                        {t!("pages-zoom-fit")}
                    }
                    span { class: "mx-1 h-5 w-px bg-line" }
                    button {
                        class: "btn btn-sm btn-secondary font-mono",
                        disabled: cur <= 1,
                        onclick: move |_| {
                            let p = current_page.peek().saturating_sub(1).max(1);
                            goto_page(p);
                        },
                        "‹"
                    }
                    span { class: "text-sm text-fg-muted whitespace-nowrap",
                        {t!("pages-page-of", page: cur, count: page_count)}
                    }
                    button {
                        class: "btn btn-sm btn-secondary font-mono",
                        disabled: cur >= page_count,
                        onclick: move |_| {
                            let p = (*current_page.peek() + 1).min(page_count.max(1));
                            goto_page(p);
                        },
                        "›"
                    }
                }
            }

            // ── Body ────────────────────────────────────────────────
            if status == "failed" {
                Card {
                    div { class: "p-5 text-sm text-danger",
                        {t!("pages-failed", error: error_text.clone())}
                    }
                }
            } else if status == "unavailable" || status == "unsupported" {
                Card {
                    div { class: "p-5 text-sm text-fg-muted", "{error_text}" }
                }
            } else if pages_list.is_empty() {
                // Pending (or manifest not loaded yet) with nothing rendered.
                Card {
                    div { class: "p-5 flex items-center gap-3",
                        svg {
                            class: "animate-spin h-5 w-5 text-brand",
                            fill: "none",
                            view_box: "0 0 24 24",
                            circle {
                                class: "opacity-25",
                                cx: "12", cy: "12", r: "10",
                                stroke: "currentColor", stroke_width: "4",
                            }
                            path {
                                class: "opacity-75",
                                fill: "currentColor",
                                d: "M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z",
                            }
                        }
                        span { class: "text-sm text-fg-muted", {t!("pages-pending")} }
                    }
                }
            } else {
                div {
                    id: "mv-pages-scroll",
                    class: "flex-1 min-h-0 overflow-auto rounded border border-line bg-surface-2 p-6",
                    for (page_no, width, height) in pages_list.iter().copied() {
                        PageView {
                            key: "{page_no}",
                            cid: cid.clone(),
                            page_no,
                            width,
                            height,
                            zoom: zoom_val,
                        }
                    }
                }
            }
        }
    }
}

/// One rendered page: the raster image plus a lazily fetched selectable
/// text layer. The text layer is requested when the page first scrolls
/// into view (`onvisible` — IntersectionObserver under the hood); a miss
/// (layer not rendered yet) re-arms so the next visibility event retries.
#[component]
fn PageView(cid: String, page_no: u32, width: u32, height: u32, zoom: f64) -> Element {
    let mut layer = use_signal(|| None::<TextLayerView>);
    let mut requested = use_signal(|| false);

    let outer_w = (width as f64 * zoom).round() as u32;
    let outer_h = (height as f64 * zoom).round() as u32;
    let img_src = format!("/api/v1/files/{cid}/pages/{page_no}/image");
    let fetch_cid = cid.clone();

    rsx! {
        div {
            id: "page-{page_no}",
            class: "relative mx-auto mb-6 shadow border border-line bg-white overflow-hidden",
            style: "width: {outer_w}px; height: {outer_h}px;",
            onvisible: move |evt| {
                if *requested.peek() || layer.peek().is_some() {
                    return;
                }
                if !evt.data().is_intersecting().unwrap_or(true) {
                    return;
                }
                requested.set(true);
                let cid = fetch_cid.clone();
                spawn(async move {
                    match get_page_text_layer(cid, page_no).await {
                        Ok(Some(l)) => layer.set(Some(l)),
                        // Not available yet — allow a retry on the next
                        // visibility change.
                        _ => requested.set(false),
                    }
                });
            },
            // Natural pixel size, scaled as one unit so image and text
            // layer can never drift apart.
            div {
                class: "relative",
                style: "width: {width}px; height: {height}px; transform: scale({zoom}); transform-origin: 0 0;",
                img {
                    src: "{img_src}",
                    loading: "lazy",
                    decoding: "async",
                    draggable: false,
                    class: "absolute inset-0 w-full h-full select-none pointer-events-none",
                }
                if let Some(l) = &*layer.read() {
                    div { class: "mv-textlayer absolute inset-0",
                        for (text, x, y, w, h) in l.words.iter() {
                            span {
                                style: "position:absolute; left:{x}px; top:{y}px; width:{w}px; height:{h}px; font-size:{h}px; line-height:1;",
                                // Trailing space → word boundaries on copy.
                                "{text} "
                            }
                        }
                    }
                }
            }
        }
    }
}
