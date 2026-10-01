//! Signing in to the web UI with OpenID Connect (`MEMVAULT_UI_AUTH=oidc`).
//!
//! Configured by environment variables:
//!
//! - `MEMVAULT_OIDC_ISSUER`, `MEMVAULT_OIDC_CLIENT_ID`,
//!   `MEMVAULT_OIDC_CLIENT_SECRET`: the provider and this client.
//! - `MEMVAULT_OIDC_REDIRECT_URL`: where the provider sends people back,
//!   `<the UI's URL>/auth/oidc/callback`.
//! - `MEMVAULT_OIDC_SCOPES` (optional): the scopes asked for, separated by
//!   spaces or commas (default `email profile`; `openid` is always asked).
//! - `MEMVAULT_OIDC_ALLOWED` (optional): who may sign in, comma-separated
//!   addresses and `@domain`s. Unset: anyone the provider signs in.
//! - `MEMVAULT_OIDC_AGENTS` (optional): `address=agent` pairs,
//!   comma-separated. A mapped address acts as that local agent: its
//!   identity directory (a path, or a name under `MEMVAULT_OIDC_AGENTS_DIR`,
//!   default `<data dir>/agents`). Everyone else acts as the daemon's `_ui`
//!   agent.
//!
//! Signing in puts an agent JWT in the UI's session cookie; from then on the
//! UI works as that agent (see `ui::state::client`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;

/// How long a sign-in may take between leaving and coming back.
const PENDING_TTL: Duration = Duration::from_secs(600);
/// How long a session lasts (the agent JWT in the cookie).
const SESSION_TTL: u64 = 8 * 3600;

#[derive(Clone, Debug, PartialEq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    /// Scopes asked for besides `openid`.
    pub scopes: Vec<String>,
    /// Addresses and `@domain`s (lower-case); empty = anyone.
    pub allowed: Vec<String>,
    /// Address (lower-case) → agent identity directory.
    pub agents: HashMap<String, PathBuf>,
}

impl OidcConfig {
    /// From `MEMVAULT_OIDC_*`; `agents_dir` resolves agent names.
    pub fn from_env(agents_dir: &std::path::Path) -> Result<Self, String> {
        Self::from_vars(|k| std::env::var(k).ok(), agents_dir)
    }

    /// From any source of variables (tests).
    pub fn from_vars(
        get: impl Fn(&str) -> Option<String>,
        agents_dir: &std::path::Path,
    ) -> Result<Self, String> {
        let var = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let need = |k: &str| var(k).ok_or_else(|| format!("MEMVAULT_UI_AUTH=oidc needs {k}"));
        let dir = var("MEMVAULT_OIDC_AGENTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| agents_dir.to_path_buf());
        Ok(OidcConfig {
            issuer: need("MEMVAULT_OIDC_ISSUER")?,
            client_id: need("MEMVAULT_OIDC_CLIENT_ID")?,
            client_secret: need("MEMVAULT_OIDC_CLIENT_SECRET")?,
            redirect_url: need("MEMVAULT_OIDC_REDIRECT_URL")?,
            scopes: var("MEMVAULT_OIDC_SCOPES")
                .unwrap_or_else(|| "email profile".into())
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty() && *s != "openid")
                .map(String::from)
                .collect(),
            allowed: list(&var("MEMVAULT_OIDC_ALLOWED").unwrap_or_default())
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            agents: agents(&var("MEMVAULT_OIDC_AGENTS").unwrap_or_default(), &dir)?,
        })
    }

    /// May this address sign in?
    pub fn allows(&self, email: &str) -> bool {
        let email = email.to_lowercase();
        self.allowed.is_empty()
            || self.allowed.iter().any(|a| {
                if a.starts_with('@') {
                    email.ends_with(a.as_str())
                } else {
                    *a == email
                }
            })
    }

    /// The local agent an address acts as, if it's mapped.
    pub fn agent_for(&self, email: &str) -> Option<&PathBuf> {
        self.agents.get(&email.to_lowercase())
    }
}

fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn agents(v: &str, dir: &std::path::Path) -> Result<HashMap<String, PathBuf>, String> {
    let mut out = HashMap::new();
    for pair in list(v) {
        let (email, agent) = pair
            .split_once('=')
            .ok_or_else(|| format!("MEMVAULT_OIDC_AGENTS: {pair:?} isn't address=agent"))?;
        let agent = agent.trim();
        let path = if agent.contains('/') {
            PathBuf::from(agent)
        } else {
            dir.join(agent)
        };
        out.insert(email.trim().to_lowercase(), path);
    }
    Ok(out)
}

/// A sign-in in progress: its PKCE verifier and nonce, by CSRF state.
type Pending = Mutex<HashMap<String, (PkceCodeVerifier, Nonce, Instant)>>;

struct Oidc {
    cfg: OidcConfig,
    meta: CoreProviderMetadata,
    redirect: RedirectUrl,
    http: openidconnect::reqwest::Client,
    pending: Pending,
}

static OIDC: OnceLock<Arc<Oidc>> = OnceLock::new();

/// Discovers the provider and enables the sign-in routes. Call once at start.
pub async fn init(cfg: OidcConfig) -> Result<(), String> {
    // Redirects are refused: the provider's endpoints answer directly (SSRF guard).
    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let issuer =
        IssuerUrl::new(cfg.issuer.clone()).map_err(|e| format!("MEMVAULT_OIDC_ISSUER: {e}"))?;
    let redirect = RedirectUrl::new(cfg.redirect_url.clone())
        .map_err(|e| format!("MEMVAULT_OIDC_REDIRECT_URL: {e}"))?;
    let meta = CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|e| format!("discovering {}: {e}", cfg.issuer))?;
    let _ = OIDC.set(Arc::new(Oidc {
        cfg,
        meta,
        redirect,
        http,
        pending: Mutex::default(),
    }));
    Ok(())
}

fn oidc() -> Result<Arc<Oidc>, Response> {
    OIDC.get().cloned().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC sign-in isn't configured",
        )
            .into_response()
    })
}

/// `/auth/oidc/login`: off to the provider.
async fn login() -> Response {
    let o = match oidc() {
        Ok(o) => o,
        Err(r) => return r,
    };
    let client = CoreClient::from_provider_metadata(
        o.meta.clone(),
        ClientId::new(o.cfg.client_id.clone()),
        Some(ClientSecret::new(o.cfg.client_secret.clone())),
    )
    .set_redirect_uri(o.redirect.clone());
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(o.cfg.scopes.iter().map(|s| Scope::new(s.clone())))
        .set_pkce_challenge(challenge)
        .url();
    {
        let mut pending = o.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, (_, _, at)| at.elapsed() < PENDING_TTL);
        pending.insert(csrf.secret().clone(), (verifier, nonce, Instant::now()));
    }
    Redirect::to(url.as_str()).into_response()
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `/auth/oidc/callback`: the provider says who it is; sign in as the
/// mapped agent or `_ui`.
async fn callback(jar: CookieJar, Query(q): Query<Callback>) -> Response {
    let o = match oidc() {
        Ok(o) => o,
        Err(r) => return r,
    };
    let denied = |msg: String| {
        tracing::warn!("OIDC sign-in refused: {msg}");
        (StatusCode::FORBIDDEN, msg).into_response()
    };
    if let Some(e) = q.error {
        return denied(format!("the provider said: {e}"));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return denied("no code from the provider".into());
    };
    let Some((verifier, nonce, _)) = o
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&state)
    else {
        return denied("unknown or expired sign-in (start again)".into());
    };
    let client = CoreClient::from_provider_metadata(
        o.meta.clone(),
        ClientId::new(o.cfg.client_id.clone()),
        Some(ClientSecret::new(o.cfg.client_secret.clone())),
    )
    .set_redirect_uri(o.redirect.clone());
    let exchange = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(x) => x,
        Err(e) => return denied(format!("the provider has no token endpoint: {e}")),
    };
    let tokens = match exchange
        .set_pkce_verifier(verifier)
        .request_async(&o.http)
        .await
    {
        Ok(t) => t,
        Err(e) => return denied(format!("exchanging the code: {e}")),
    };
    let Some(id_token) = tokens.id_token() else {
        return denied("the provider sent no ID token".into());
    };
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => return denied(format!("the ID token: {e}")),
    };
    let Some(email) = claims.email().map(|e| e.as_str().to_string()) else {
        return denied("the provider shared no email address".into());
    };
    if claims.email_verified() == Some(false) {
        return denied(format!("{email} isn't verified with the provider"));
    }
    if !o.cfg.allows(&email) {
        return denied(format!("{email} may not sign in here"));
    }
    let token = match o.cfg.agent_for(&email) {
        // A mapped address acts as that local agent.
        Some(dir) => match memvault_api::agent_identity::AgentIdentity::load(dir)
            .and_then(|id| id.issue_jwt("read write", SESSION_TTL))
        {
            Ok(t) => t,
            Err(e) => return denied(format!("{email}'s agent ({}): {e}", dir.display())),
        },
        None => match crate::ui::state::ui_agent_identity()
            .map(|id| id.issue_jwt("read write admin", SESSION_TTL))
        {
            Some(Ok(t)) => t,
            _ => {
                return (StatusCode::SERVICE_UNAVAILABLE, "the UI agent isn't ready")
                    .into_response();
            }
        },
    };
    tracing::info!(%email, agent = o.cfg.agent_for(&email).map(|d| d.display().to_string()).unwrap_or_else(|| "_ui".into()), "signed in to the web UI");
    (
        jar.add(crate::api::auth::session_cookie(token)),
        Redirect::to("/"),
    )
        .into_response()
}

/// `/auth/oidc/logout`: forget the session.
async fn logout(jar: CookieJar) -> Response {
    (
        jar.remove(axum_extra::extract::cookie::Cookie::from(
            crate::api::auth::SESSION_COOKIE,
        )),
        Redirect::to("/"),
    )
        .into_response()
}

/// The sign-in routes.
pub fn routes() -> Router {
    Router::new()
        .route("/auth/oidc/login", get(login))
        .route("/auth/oidc/callback", get(callback))
        .route("/auth/oidc/logout", get(logout))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &[(&str, &str)]) -> Result<OidcConfig, String> {
        let mut vars: HashMap<&str, &str> = HashMap::from([
            ("MEMVAULT_OIDC_ISSUER", "https://id.example.org"),
            ("MEMVAULT_OIDC_CLIENT_ID", "mv"),
            ("MEMVAULT_OIDC_CLIENT_SECRET", "s"),
            (
                "MEMVAULT_OIDC_REDIRECT_URL",
                "http://127.0.0.1:8411/auth/oidc/callback",
            ),
        ]);
        vars.extend(extra.iter().copied());
        OidcConfig::from_vars(
            |k| vars.get(k).map(|v| v.to_string()),
            std::path::Path::new("/data/agents"),
        )
    }

    #[test]
    fn who_may_sign_in_and_as_whom() {
        let c = cfg(&[
            ("MEMVAULT_OIDC_ALLOWED", "Ann@Example.org, @lab.org"),
            (
                "MEMVAULT_OIDC_AGENTS",
                "ann@example.org=team-a, bob@lab.org=/srv/ids/bob",
            ),
        ])
        .unwrap();
        assert!(c.allows("ann@example.org") && c.allows("anyone@lab.org"));
        assert!(!c.allows("eve@example.org") && !c.allows("eve@notlab.org"));
        assert_eq!(
            c.agent_for("ANN@example.org"),
            Some(&PathBuf::from("/data/agents/team-a"))
        );
        assert_eq!(
            c.agent_for("bob@lab.org"),
            Some(&PathBuf::from("/srv/ids/bob"))
        );
        assert_eq!(
            c.agent_for("carol@lab.org"),
            None,
            "unmapped: the _ui agent"
        );
        assert!(
            cfg(&[]).unwrap().allows("anyone@anywhere.org"),
            "no list: anyone"
        );
        assert_eq!(cfg(&[]).unwrap().scopes, ["email", "profile"]);
        assert_eq!(
            cfg(&[("MEMVAULT_OIDC_SCOPES", "openid email,groups offline_access")])
                .unwrap()
                .scopes,
            ["email", "groups", "offline_access"]
        );
        assert!(cfg(&[("MEMVAULT_OIDC_AGENTS", "nonsense")]).is_err());
        let missing = OidcConfig::from_vars(|_| None, std::path::Path::new("/x")).unwrap_err();
        assert!(missing.contains("MEMVAULT_OIDC_ISSUER"), "{missing}");
    }
}
