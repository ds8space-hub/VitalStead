//! OAuth token exchange adapter — T-203, EPIC-03-oauth.md.
//!
//! Platform-independent trait for token exchange operations (authorization code → access token,
//! refresh token → new access token). Implementations are injected at the composition root,
//! so core modules (refresh orchestration) depend only on this trait, not on any HTTP/reqwest
//! implementation details.
//!
//! T-203 scope: orchestration logic and synchronous trait definition only.
//! Actual reqwest-backed implementation will be added during connector framework work (T-204+).

use crate::core::security::SecretString;

/// Parameters for OAuth authorization code exchange (code → token).
///
/// Used by `TokenExchangeClient::exchange_code()` during the initial OAuth authorization flow
/// to convert an authorization code into access/refresh tokens.
pub struct ExchangeCodeParams {
    /// OAuth token endpoint URL (e.g., `https://api.oura.cloud/oauth/token`)
    pub token_endpoint: String,
    /// OAuth client identifier (registered with the provider)
    pub client_id: String,
    /// OAuth client secret (if applicable; `None` for public clients)
    pub client_secret: Option<SecretString>,
    /// Authorization code received from the callback
    pub code: String,
    /// OAuth redirect URI (must match provider registration)
    pub redirect_uri: String,
}

/// Parameters for OAuth refresh token exchange (refresh token → new access token).
///
/// Used by `TokenExchangeClient::refresh_token()` to refresh an expired access token
/// using a stored refresh token.
pub struct RefreshTokenParams {
    /// OAuth token endpoint URL
    pub token_endpoint: String,
    /// OAuth client identifier
    pub client_id: String,
    /// OAuth client secret (if applicable)
    pub client_secret: Option<SecretString>,
    /// Stored refresh token
    pub refresh_token: SecretString,
}

/// Parameters for OAuth token revocation (RFC 7009).
///
/// Used by `TokenExchangeClient::revoke_token()` to revoke a token
/// (either access token or refresh token).
pub struct RevokeTokenParams {
    /// OAuth revocation endpoint URL (e.g., `https://api.oura.cloud/oauth/revoke`)
    pub revoke_endpoint: String,
    /// OAuth client identifier (registered with the provider)
    pub client_id: String,
    /// OAuth client secret (if applicable; `None` for public clients)
    pub client_secret: Option<SecretString>,
    /// Token to revoke (access token or refresh token)
    pub token: SecretString,
    /// Token type hint (per RFC 7009): `Some("access_token")` or `Some("refresh_token")`
    /// or `None` if unknown
    pub token_type_hint: Option<&'static str>,
}

/// Successful OAuth token response (access token and optional rotated refresh token).
///
/// Per credentials-and-security.md L46, refresh token rotation is provider-dependent
/// and not guaranteed on every refresh — some providers never rotate, others rotate on
/// every call, others rotate based on time/conditions.
#[derive(Clone)]
pub struct TokenResponse {
    /// New access token (ready to use in API calls)
    pub access_token: SecretString,
    /// New refresh token if the provider rotated it; `None` if provider did not rotate.
    ///
    /// Per credentials-and-security.md L46 and T-203 scoping: if `Some`, the caller
    /// (RefreshOrchestrator) overwrites the old refresh token atomically in storage.
    pub refresh_token: Option<SecretString>,
    /// Token lifetime in seconds (e.g., 3600 for 1 hour).
    ///
    /// Used to calculate `expires_at = now + expires_in_secs` for cache validity
    /// and next-refresh-due calculation (credentials-and-security.md L44).
    pub expires_in_secs: u64,
    /// OAuth scope string (ADR-021) — space-separated scope identifiers returned by provider.
    ///
    /// Per ADR-021, this is an optional, additive field for connectors that need to track
    /// granted scopes. Some providers return it; others omit it. Stored for audit/logging
    /// purposes but not used in core orchestration logic.
    pub scope: Option<String>,
}

/// Error type for token exchange operations.
///
/// Distinguishes between retryable errors (network, rate limit, 5xx) and non-retryable
/// ones (4xx client errors, invalid_grant) so the orchestration layer can apply
/// appropriate backoff and decision logic.
#[derive(Debug, Clone)]
pub enum TokenExchangeError {
    /// Network error (no connectivity, DNS failure, connection timeout, etc.)
    ///
    /// Retryable with exponential backoff per T-203 scoping (1s, 2s, 4s, then fail).
    Network(String),

    /// HTTP 429 — rate limited by provider.
    ///
    /// Retryable with backoff; `retry_after_secs` (if `Some`) overrides the default backoff table
    /// and must be capped at 60s per T-203 (credentials-and-security.md L73).
    RateLimited { retry_after_secs: Option<u64> },

    /// HTTP 5xx — server error (transient provider issue).
    ///
    /// Retryable with exponential backoff per T-203 scoping (2s, 4s, 8s, then fail).
    ServerError(u16),

    /// OAuth `invalid_grant` error — refresh token expired or was revoked.
    ///
    /// Maps to `RefreshOutcome::ReauthorizationRequired` per credentials-and-security.md L49.
    /// NOT retried. NOT an error in the result sense — application logic handles it.
    InvalidGrant,

    /// HTTP 4xx (not `invalid_grant`) — bad request, invalid client, etc.
    ///
    /// Not retried; caller handles per oauth/state machine (may map to error states).
    ClientError { status: u16, error: Option<String> },
}

/// Platform-independent token exchange client trait.
///
/// Trait object to be injected at composition root. Implementations handle all
/// HTTP/network details and provider-specific response parsing.
pub trait TokenExchangeClient: Send + Sync {
    /// Exchange an authorization code for access and refresh tokens.
    ///
    /// Used during initial OAuth authorization (T-203 mentions shape but scope
    /// defers implementation to T-204/connector work). Trait shape is defined now
    /// for architectural completeness and DI seam placement.
    fn exchange_code(&self, params: ExchangeCodeParams) -> Result<TokenResponse, TokenExchangeError>;

    /// Refresh an expired access token using a stored refresh token.
    ///
    /// The primary operation exercised by T-203 orchestration logic.
    /// Implements the OAuth 2.0 refresh token grant flow (RFC 6749 §6).
    fn refresh_token(&self, params: RefreshTokenParams) -> Result<TokenResponse, TokenExchangeError>;

    /// Revoke an access or refresh token.
    ///
    /// Implements OAuth 2.0 token revocation (RFC 7009). Best-effort operation:
    /// even if revocation fails, the caller (DisconnectOrchestrator) will delete
    /// the token from local storage. Per T-305, this returns `Ok(())` on 200 or
    /// other provider-specific success responses, mapping all errors through the
    /// same status mapping logic as `exchange_code` and `refresh_token`.
    fn revoke_token(&self, params: RevokeTokenParams) -> Result<(), TokenExchangeError>;
}
