//! Browser-side session bootstrap.
//!
//! On mount the WASM client `fetch`es `/api/v1/auth/session-token` with
//! `credentials: 'same-origin'`. The endpoint sets the `memvault_session`
//! cookie (HttpOnly, SameSite=Strict, Path=/) so every subsequent request
//! — REST + Dioxus server functions — rides along on it. The body of the
//! same response carries the agent_id + expires_at the UI needs to render
//! the "logged in as …" chip and to schedule a renewal.
//!
//! A background task wakes up `SESSION_RENEW_LEAD_SECS` before `expires_at`
//! and re-hits the same endpoint, transparent to the user.
//!
//! SSR pass: this runs only on `wasm32`, so the SSR render starts as
//! `SessionState::Loading`. The hydrated client immediately fires the
//! fetch, swaps in `SessionState::Active`, and re-renders any components
//! that read the context. No flash of "logged out" because the rest of
//! the UI doesn't gate on session state — the cookie auth on the daemon
//! side is what actually authorises requests.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Re-fetch the session this many seconds before expiry.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const SESSION_RENEW_LEAD_SECS: u64 = 300;

/// Parsed `GET /api/v1/auth/session-token` response body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub agent_id: String,
    pub ttl_secs: u64,
    /// Server-issued ms-since-epoch when this session expires. Computed
    /// client-side from `ttl_secs + now()` so we don't have to trust
    /// clock skew between the server and the browser.
    #[serde(skip)]
    pub expires_at_ms: f64,
}

/// What the rest of the UI sees about the current session.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SessionState {
    /// Initial render (SSR or pre-fetch). Treat as anonymous for display.
    #[default]
    Loading,
    /// Logged in as the daemon's auto-enrolled ui_agent (or, later,
    /// whoever the multi-user flow elects).
    Active(SessionInfo),
    /// Session probe failed (network, 503, …). The UI keeps working —
    /// requests just won't carry the cookie until the next renewal —
    /// but we show a small "session unavailable" indicator.
    Failed(String),
}

/// Session signal type that pages / components read from context.
pub type SessionSignal = Signal<SessionState>;

/// Install the session context. Call once near the root (e.g. in `Layout`).
/// Spawns the fetch and the renewal loop on the WASM side; on the server
/// side it just provides an empty `Loading` signal so SSR has something
/// to render.
pub fn use_session_provider() -> SessionSignal {
    let session = use_signal(SessionState::default);
    use_context_provider(|| session);
    #[cfg(target_arch = "wasm32")]
    let mut session = session;

    #[cfg(target_arch = "wasm32")]
    use_effect(move || {
        spawn(async move {
            loop {
                match fetch_session().await {
                    Ok(info) => {
                        let sleep_secs = info
                            .ttl_secs
                            .saturating_sub(SESSION_RENEW_LEAD_SECS)
                            .max(60);
                        session.set(SessionState::Active(info));
                        gloo_timers::future::TimeoutFuture::new(
                            (sleep_secs * 1000) as u32,
                        )
                        .await;
                    }
                    Err(e) => {
                        session.set(SessionState::Failed(e));
                        // Back off for a minute before trying again.
                        gloo_timers::future::TimeoutFuture::new(60_000).await;
                    }
                }
            }
        });
    });

    session
}

/// Convenience accessor for components that just need to know the
/// logged-in agent (or `None` if no session is active yet).
pub fn use_session() -> SessionSignal {
    use_context::<SessionSignal>()
}

#[cfg(target_arch = "wasm32")]
async fn fetch_session() -> Result<SessionInfo, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestCredentials, RequestInit, Response};

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_credentials(RequestCredentials::SameOrigin);

    let req = Request::new_with_str_and_init("/api/v1/auth/session-token", &opts)
        .map_err(|e| format!("Request init failed: {e:?}"))?;
    let _ = req.headers().set("accept", "application/json");

    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|e| format!("expected Response: {e:?}"))?;

    if !resp.ok() {
        return Err(format!("session endpoint returned {}", resp.status()));
    }

    let json_promise = resp
        .json()
        .map_err(|e| format!("response.json() failed: {e:?}"))?;
    let json_value = JsFuture::from(json_promise)
        .await
        .map_err(|e| format!("response body read failed: {e:?}"))?;
    let mut info: SessionInfo = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| format!("decode session body: {e}"))?;
    info.expires_at_ms = js_sys::Date::now() + (info.ttl_secs as f64) * 1000.0;
    Ok(info)
}

// SSR (non-wasm32) stub. The provider doesn't fetch on the server pass;
// the hydrated client will fire the real request immediately on mount.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
async fn fetch_session() -> Result<SessionInfo, String> {
    Err("session fetch is wasm-only".into())
}
