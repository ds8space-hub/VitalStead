//! OAuth token exchange client implementation using reqwest blocking HTTP.
//!
//! T-303: Synchronous HTTP client for exchanging OAuth authorization codes and refresh tokens.
//! Uses reqwest::blocking::Client (synchronous, not async) because the caller
//! (RefreshOrchestrator in src/core/oauth/refresh.rs) is synchronous and runs under std::sync::Mutex.
//!
//! Security: No logging of tokens, client secrets, or error_description fields.
//! Per D-015, secrets never enter model context. SecretString requires explicit expose_secret().

use crate::adapters::{
    ExchangeCodeParams, RefreshTokenParams, RevokeTokenParams, TokenExchangeClient,
    TokenExchangeError, TokenResponse,
};
use crate::core::security::SecretString;
use serde::Deserialize;
use std::time::Duration;

/// Successful OAuth token response from provider (JSON).
/// Struct names match OAuth 2.0 standard (RFC 6749 §5.1).
#[derive(Debug, Deserialize)]
struct TokenResponseDto {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
    /// OAuth scope field (ADR-021) — per RFC 6749 §5.1, optional.
    /// Some providers omit; others include space-separated scope string.
    #[serde(default)]
    scope: Option<String>,
}

/// OAuth error response from provider (JSON).
/// Per D-015, error_description is not captured — it is free-form provider text
/// and must never enter logs or error output.
#[derive(Debug, Deserialize, Default)]
struct OAuthErrorDto {
    error: Option<String>,
    // error_description intentionally NOT captured — opaque by default per D-015.
}

/// Synchronous OAuth token exchange client.
///
/// Uses reqwest::blocking::Client for synchronous HTTP requests with:
/// - 30-second overall timeout
/// - 5-second connect timeout
/// - TLS via rustls (no OpenSSL dependency)
/// - Form-encoded request bodies (RFC 6749)
pub struct ReqwestTokenExchangeClient {
    client: reqwest::blocking::Client,
}

impl ReqwestTokenExchangeClient {
    /// Create a new token exchange client with production timeouts.
    ///
    /// Timeouts:
    /// - Overall request: 30 seconds
    /// - Initial connection: 5 seconds
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client construction with static config must not fail");
        ReqwestTokenExchangeClient { client }
    }

    /// Create a client with custom timeout (for testing without waiting real duration).
    ///
    /// This is a testability seam — allows tests to verify timeout behavior
    /// without sleeping for 30 seconds. Only available in test builds.
    #[cfg(test)]
    pub(crate) fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client construction with static config must not fail");
        ReqwestTokenExchangeClient { client }
    }
}

impl Default for ReqwestTokenExchangeClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenExchangeClient for ReqwestTokenExchangeClient {
    fn exchange_code(&self, params: ExchangeCodeParams) -> Result<TokenResponse, TokenExchangeError> {
        let mut form_params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", params.code),
            ("redirect_uri", params.redirect_uri),
            ("client_id", params.client_id.clone()),
        ];

        // client_secret_post (RFC 6749 §2.3.1): client_id/client_secret as form
        // fields, NOT HTTP Basic Auth. Confirmed against WHOOP's real token
        // endpoint on manual e2e (T-401) — Basic Auth got 401 invalid_client;
        // WHOOP's own docs example also shows client_secret in the body.
        if let Some(secret) = &params.client_secret {
            form_params.push(("client_secret", secret.expose_secret().to_string()));
        }

        let request = self.client.post(&params.token_endpoint).form(&form_params);

        // Send request and map errors
        let response = match request.send() {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "OAuth token exchange network error");
                return Err(TokenExchangeError::Network(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        tracing::debug!(status, "OAuth token exchange response received");

        // Map HTTP status to TokenExchangeError, reading body once.
        match status {
            200 => {
                // Success: parse TokenResponseDto
                match response.json::<TokenResponseDto>() {
                    Ok(dto) => {
                        tracing::debug!("OAuth token exchange success");
                        Ok(TokenResponse {
                            access_token: SecretString::new(dto.access_token),
                            refresh_token: dto.refresh_token.map(SecretString::new),
                            expires_in_secs: dto.expires_in,
                            scope: dto.scope,
                        })
                    }
                    Err(_parse_err) => {
                        // 2xx with malformed JSON → fallback to ServerError
                        tracing::warn!(status, "OAuth token exchange 2xx with malformed JSON body");
                        Err(TokenExchangeError::ServerError(status))
                    }
                }
            }
            429 => {
                // Rate limited: try to parse Retry-After header
                let retry_after_secs = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                tracing::warn!(retry_after_secs, "OAuth token exchange rate limited");
                Err(TokenExchangeError::RateLimited { retry_after_secs })
            }
            400..=499 => {
                // Client error: try to parse error response
                match response.json::<OAuthErrorDto>() {
                    Ok(error_dto) => {
                        if status == 400 && matches!(&error_dto.error, Some(e) if e == "invalid_grant") {
                            tracing::warn!("OAuth token exchange invalid_grant error");
                            Err(TokenExchangeError::InvalidGrant)
                        } else {
                            let error_code = error_dto.error.clone();
                            tracing::warn!(status, error_kind = ?error_code, "OAuth token exchange client error");
                            Err(TokenExchangeError::ClientError {
                                status,
                                error: error_code,
                            })
                        }
                    }
                    Err(_parse_err) => {
                        // 4xx with malformed JSON → map by status only
                        tracing::warn!(status, "OAuth token exchange 4xx with malformed JSON body");
                        if status == 429 {
                            Err(TokenExchangeError::RateLimited {
                                retry_after_secs: None,
                            })
                        } else {
                            Err(TokenExchangeError::ClientError {
                                status,
                                error: None,
                            })
                        }
                    }
                }
            }
            500..=599 => {
                tracing::warn!(status, "OAuth token exchange server error");
                Err(TokenExchangeError::ServerError(status))
            }
            _ => {
                // Unexpected status code
                tracing::warn!(status, "OAuth token exchange unexpected status");
                Err(TokenExchangeError::ServerError(status))
            }
        }
    }

    fn refresh_token(&self, params: RefreshTokenParams) -> Result<TokenResponse, TokenExchangeError> {
        let mut form_params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", params.refresh_token.expose_secret().to_string()),
            ("client_id", params.client_id.clone()),
        ];

        // client_secret_post (RFC 6749 §2.3.1) — see exchange_code() for the
        // e2e-verified rationale (WHOOP requires body params, not Basic Auth).
        if let Some(secret) = &params.client_secret {
            form_params.push(("client_secret", secret.expose_secret().to_string()));
        }

        let request = self.client.post(&params.token_endpoint).form(&form_params);

        // Send request and map errors (same logic as exchange_code)
        let response = match request.send() {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "OAuth token refresh network error");
                return Err(TokenExchangeError::Network(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        tracing::debug!(status, "OAuth token refresh response received");

        // Map HTTP status to TokenExchangeError
        match status {
            200 => {
                match response.json::<TokenResponseDto>() {
                    Ok(dto) => {
                        tracing::debug!("OAuth token refresh success");
                        Ok(TokenResponse {
                            access_token: SecretString::new(dto.access_token),
                            refresh_token: dto.refresh_token.map(SecretString::new),
                            expires_in_secs: dto.expires_in,
                            scope: dto.scope,
                        })
                    }
                    Err(_parse_err) => {
                        tracing::warn!(status, "OAuth token refresh 2xx with malformed JSON body");
                        Err(TokenExchangeError::ServerError(status))
                    }
                }
            }
            429 => {
                let retry_after_secs = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                tracing::warn!(retry_after_secs, "OAuth token refresh rate limited");
                Err(TokenExchangeError::RateLimited { retry_after_secs })
            }
            400..=499 => {
                match response.json::<OAuthErrorDto>() {
                    Ok(error_dto) => {
                        if status == 400 && matches!(&error_dto.error, Some(e) if e == "invalid_grant") {
                            tracing::warn!("OAuth token refresh invalid_grant error");
                            Err(TokenExchangeError::InvalidGrant)
                        } else {
                            let error_code = error_dto.error.clone();
                            tracing::warn!(status, error_kind = ?error_code, "OAuth token refresh client error");
                            Err(TokenExchangeError::ClientError {
                                status,
                                error: error_code,
                            })
                        }
                    }
                    Err(_parse_err) => {
                        tracing::warn!(status, "OAuth token refresh 4xx with malformed JSON body");
                        if status == 429 {
                            Err(TokenExchangeError::RateLimited {
                                retry_after_secs: None,
                            })
                        } else {
                            Err(TokenExchangeError::ClientError {
                                status,
                                error: None,
                            })
                        }
                    }
                }
            }
            500..=599 => {
                tracing::warn!(status, "OAuth token refresh server error");
                Err(TokenExchangeError::ServerError(status))
            }
            _ => {
                tracing::warn!(status, "OAuth token refresh unexpected status");
                Err(TokenExchangeError::ServerError(status))
            }
        }
    }

    fn revoke_token(&self, params: RevokeTokenParams) -> Result<(), TokenExchangeError> {
        let mut form_params = vec![("token", params.token.expose_secret().to_string())];

        // Add optional token_type_hint
        if let Some(hint) = params.token_type_hint {
            form_params.push(("token_type_hint", hint.to_string()));
        }

        form_params.push(("client_id", params.client_id.clone()));

        // client_secret_post (RFC 6749 §2.3.1) — see exchange_code() for the
        // e2e-verified rationale (WHOOP requires body params, not Basic Auth).
        if let Some(secret) = &params.client_secret {
            form_params.push(("client_secret", secret.expose_secret().to_string()));
        }

        let request = self.client.post(&params.revoke_endpoint).form(&form_params);

        // Send request and map errors
        let response = match request.send() {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "OAuth token revocation network error");
                return Err(TokenExchangeError::Network(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        tracing::debug!(status, "OAuth token revocation response received");

        // Per RFC 7009, server should respond 200 even if token was already invalid/revoked.
        // Map HTTP status to TokenExchangeError using same logic as exchange/refresh.
        match status {
            200 => {
                tracing::debug!("OAuth token revocation success");
                Ok(())
            }
            429 => {
                let retry_after_secs = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                tracing::warn!(retry_after_secs, "OAuth token revocation rate limited");
                Err(TokenExchangeError::RateLimited { retry_after_secs })
            }
            400..=499 => {
                match response.json::<OAuthErrorDto>() {
                    Ok(error_dto) => {
                        let error_code = error_dto.error.clone();
                        tracing::warn!(status, error_kind = ?error_code, "OAuth token revocation client error");
                        Err(TokenExchangeError::ClientError {
                            status,
                            error: error_code,
                        })
                    }
                    Err(_parse_err) => {
                        tracing::warn!(status, "OAuth token revocation 4xx with malformed JSON body");
                        Err(TokenExchangeError::ClientError {
                            status,
                            error: None,
                        })
                    }
                }
            }
            500..=599 => {
                tracing::warn!(status, "OAuth token revocation server error");
                Err(TokenExchangeError::ServerError(status))
            }
            _ => {
                tracing::warn!(status, "OAuth token revocation unexpected status");
                Err(TokenExchangeError::ServerError(status))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Minimal HTTP/1.1 mock server for testing.
    /// Binds 127.0.0.1:0, spawns thread, accepts ONE connection, reads request,
    /// responds with status+body, returns (port, request_capture).
    pub(crate) fn spawn_mock_token_endpoint(
        status: u16,
        body: &'static str,
        headers: &[(&str, &str)],
    ) -> (u16, Arc<Mutex<Option<CapturedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
        let port = listener.local_addr().expect("local_addr").port();
        let captured = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

        // Clone headers to owned data for thread
        let headers_owned: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        thread::spawn(move || {
            if let Ok((mut stream, _addr)) = listener.accept() {
                let mut buf = [0u8; 8192];
                if let Ok(n) = stream.read(&mut buf) {
                    let request_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    let mut lines = request_str.lines();
                    let request_line = lines.next().unwrap_or("").to_string();

                    // Capture Authorization header and form body
                    let mut auth_header = None;
                    let mut form_body = String::new();
                    for line in lines {
                        if line.starts_with("Authorization:") {
                            auth_header = Some(line[15..].trim().to_string());
                        }
                        if line.is_empty() {
                            break;
                        }
                    }
                    // After empty line is the body
                    if let Some(body_start) = request_str.find("\r\n\r\n") {
                        form_body = request_str[body_start + 4..].to_string();
                    }

                    *captured_clone.lock().unwrap() = Some(CapturedRequest {
                        request_line,
                        auth_header,
                        form_body,
                    });
                }

                // Write response
                let status_text = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "Error",
                };

                let header_str = headers_owned
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\r\n");

                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n{}\r\n\r\n{}",
                    status, status_text, body.len(), header_str, body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        // Small delay for thread to bind
        thread::sleep(Duration::from_millis(50));

        (port, captured)
    }

    #[derive(Debug, Clone)]
    pub(crate) struct CapturedRequest {
        pub(crate) request_line: String,
        pub(crate) auth_header: Option<String>,
        pub(crate) form_body: String,
    }

    // ============ Test 1: success ============
    #[test]
    fn test_exchange_code_success_returns_token_response() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","refresh_token":"new_refresh","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.access_token.expose_secret(), "new_access");
        assert_eq!(response.refresh_token.as_ref().map(|r| r.expose_secret()), Some("new_refresh"));
        assert_eq!(response.expires_in_secs, 3600);
    }

    // ============ Test 2: form body with grant_type code ============
    #[test]
    fn test_exchange_code_sends_form_encoded_body_with_grant_type_code() {
        let (port, captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let _ = client.exchange_code(params);
        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.request_line.starts_with("POST "));
            assert!(captured_req.form_body.contains("grant_type=authorization_code"));
            assert!(captured_req.form_body.contains("code=auth_code"));
            assert!(captured_req.form_body.contains("redirect_uri="));
        }
    }

    // ============ Test 3: client_secret_post — client_secret in form body, no Basic Auth ============
    // client_secret_post (RFC 6749 §2.3.1), not HTTP Basic Auth — confirmed against
    // WHOOP's real token endpoint on manual e2e (T-401): Basic Auth got 401
    // invalid_client; WHOOP's own docs example shows client_secret in the body.
    #[test]
    fn test_exchange_code_with_client_secret_sends_it_in_form_body_no_basic_auth() {
        let (port, captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let client_id = "test_client";
        let client_secret = "test_secret";
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: client_id.to_string(),
            client_secret: Some(SecretString::new(client_secret.to_string())),
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let _ = client.exchange_code(params);
        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            // No Authorization header — client_secret_post, not Basic Auth.
            assert!(captured_req.auth_header.is_none());
            // client_id and client_secret are both in the form body.
            assert!(captured_req.form_body.contains("client_id=test_client"));
            assert!(captured_req.form_body.contains("client_secret=test_secret"));
        }
    }

    // ============ Test 4: client_id in body when no client_secret ============
    #[test]
    fn test_exchange_code_without_client_secret_sends_client_id_in_body_no_auth_header() {
        let (port, captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: None,
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let _ = client.exchange_code(params);
        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            // No Authorization header
            assert!(captured_req.auth_header.is_none());
            // client_id in form body
            assert!(captured_req.form_body.contains("client_id=test_client"));
        }
    }

    // ============ Test 5: refresh_token success without rotation ============
    #[test]
    fn test_refresh_token_success_returns_token_response() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access_refreshed","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("old_refresh".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.access_token.expose_secret(), "new_access_refreshed");
        assert!(response.refresh_token.is_none()); // Provider did not rotate
        assert_eq!(response.expires_in_secs, 3600);
    }

    // ============ Test 6: refresh_token form body ============
    #[test]
    fn test_refresh_token_sends_form_encoded_body_with_grant_type_refresh_token() {
        let (port, captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("test_refresh_token".to_string()),
        };

        let _ = client.refresh_token(params);
        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.form_body.contains("grant_type=refresh_token"));
            assert!(captured_req.form_body.contains("refresh_token="));
        }
    }

    // ============ Test 7: 400 invalid_grant ============
    #[test]
    fn test_400_invalid_grant_maps_to_invalid_grant_error() {
        let (port, _captured) = spawn_mock_token_endpoint(
            400,
            r#"{"error":"invalid_grant"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("expired_token".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(matches!(result, Err(TokenExchangeError::InvalidGrant)));
    }

    // ============ Test 8: 400 other error ============
    #[test]
    fn test_400_other_error_maps_to_client_error_with_status_and_error_field() {
        let (port, _captured) = spawn_mock_token_endpoint(
            400,
            r#"{"error":"invalid_request"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "bad_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(
            result,
            Err(TokenExchangeError::ClientError { status: 400, error: Some(_) })
        ));
    }

    // ============ Test 9: 401 ============
    #[test]
    fn test_401_maps_to_client_error() {
        let (port, _captured) = spawn_mock_token_endpoint(
            401,
            r#"{"error":"unauthorized_client"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "bad_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(
            result,
            Err(TokenExchangeError::ClientError { status: 401, .. })
        ));
    }

    // ============ Test 10: 429 with Retry-After ============
    #[test]
    fn test_429_with_retry_after_header_parses_seconds() {
        let (port, _captured) =
            spawn_mock_token_endpoint(429, r#"{"error":"rate_limit_exceeded"}"#, &[("Retry-After", "30")]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("token".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(matches!(
            result,
            Err(TokenExchangeError::RateLimited { retry_after_secs: Some(30) })
        ));
    }

    // ============ Test 11: 429 without Retry-After ============
    #[test]
    fn test_429_without_retry_after_header_returns_none() {
        let (port, _captured) = spawn_mock_token_endpoint(429, r#"{"error":"rate_limit_exceeded"}"#, &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("token".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(matches!(
            result,
            Err(TokenExchangeError::RateLimited { retry_after_secs: None })
        ));
    }

    // ============ Test 12: 429 with non-numeric Retry-After ============
    #[test]
    fn test_429_with_non_numeric_retry_after_returns_none() {
        let (port, _captured) = spawn_mock_token_endpoint(
            429,
            r#"{"error":"rate_limit_exceeded"}"#,
            &[("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("token".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(matches!(
            result,
            Err(TokenExchangeError::RateLimited { retry_after_secs: None })
        ));
    }

    // ============ Test 13: 500 ============
    #[test]
    fn test_500_maps_to_server_error_with_status() {
        let (port, _captured) = spawn_mock_token_endpoint(500, "Internal Server Error", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(result, Err(TokenExchangeError::ServerError(500))));
    }

    // ============ Test 14: 503 ============
    #[test]
    fn test_503_maps_to_server_error_with_status() {
        let (port, _captured) = spawn_mock_token_endpoint(503, "Service Unavailable", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(result, Err(TokenExchangeError::ServerError(503))));
    }

    // ============ Test 15: Network error ============
    #[test]
    fn test_network_error_maps_to_network_variant() {
        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: "http://127.0.0.1:1/token".to_string(), // Port 1 unlikely to accept
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("test_secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(result, Err(TokenExchangeError::Network(_))));

        // Verify the error message does NOT contain the secret
        if let Err(TokenExchangeError::Network(msg)) = result {
            assert!(!msg.contains("test_secret"));
        }
    }

    // ============ Test 16: Timeout ============
    #[test]
    fn test_timeout_configured_as_30_seconds() {
        // Use a client with very short timeout (200ms)
        let client = ReqwestTokenExchangeClient::with_timeout(Duration::from_millis(200));

        // Create a mock server that never responds (intentionally slow)
        let slow_port = spawn_mock_token_endpoint_slow(100_000); // 100 second delay

        let params_slow = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", slow_port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params_slow);
        assert!(matches!(result, Err(TokenExchangeError::Network(_))));
    }

    // ============ Test 17: 2xx with malformed JSON ============
    #[test]
    fn test_2xx_with_malformed_json_body_falls_back_to_server_error() {
        let (port, _captured) = spawn_mock_token_endpoint(200, "not a json response", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(matches!(result, Err(TokenExchangeError::ServerError(200))));
    }

    // ============ Test 18: error_description NOT exposed in error output ============
    #[test]
    fn test_error_response_error_description_not_exposed_in_any_error_variant() {
        let (port, _captured) = spawn_mock_token_endpoint(
            400,
            r#"{"error":"invalid_request","error_description":"client secret abc123SECRET is wrong"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(result.is_err());

        // Verify error does not contain error_description secrets
        if let Err(e) = result {
            let error_debug = format!("{:?}", e);
            assert!(
                !error_debug.contains("abc123SECRET"),
                "error_description should never appear in error output"
            );
            assert!(
                !error_debug.contains("client secret"),
                "error_description should never appear in error output"
            );
        }
    }

    // ============ Test 19: revoke_token success 200 ============
    #[test]
    fn test_revoke_token_success_sends_form_encoded_body_with_token() {
        let (port, captured) = spawn_mock_token_endpoint(200, "", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RevokeTokenParams {
            revoke_endpoint: format!("http://127.0.0.1:{}/revoke", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            token: SecretString::new("token_to_revoke".to_string()),
            token_type_hint: None,
        };

        let result = client.revoke_token(params);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.request_line.starts_with("POST "));
            assert!(captured_req.form_body.contains("token=token_to_revoke"));
        }
    }

    // ============ Test 20: revoke_token with token_type_hint ============
    #[test]
    fn test_revoke_token_with_type_hint_included_in_body() {
        let (port, captured) = spawn_mock_token_endpoint(200, "", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RevokeTokenParams {
            revoke_endpoint: format!("http://127.0.0.1:{}/revoke", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            token: SecretString::new("refresh_token_value".to_string()),
            token_type_hint: Some("refresh_token"),
        };

        let result = client.revoke_token(params);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.form_body.contains("token_type_hint=refresh_token"));
        }
    }

    // ============ Test 21: revoke_token with client_secret sends it in form body, no Basic Auth ============
    #[test]
    fn test_revoke_token_with_client_secret_sends_it_in_form_body_no_basic_auth() {
        let (port, captured) = spawn_mock_token_endpoint(200, "", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let client_id = "test_client";
        let client_secret = "test_secret";
        let params = RevokeTokenParams {
            revoke_endpoint: format!("http://127.0.0.1:{}/revoke", port),
            client_id: client_id.to_string(),
            client_secret: Some(SecretString::new(client_secret.to_string())),
            token: SecretString::new("token".to_string()),
            token_type_hint: None,
        };

        let result = client.revoke_token(params);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.auth_header.is_none());
            assert!(captured_req.form_body.contains("client_secret=test_secret"));
        }
    }

    // ============ Test 22: revoke_token without client_secret sends client_id in body ============
    #[test]
    fn test_revoke_token_without_client_secret_sends_client_id_in_body() {
        let (port, captured) = spawn_mock_token_endpoint(200, "", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RevokeTokenParams {
            revoke_endpoint: format!("http://127.0.0.1:{}/revoke", port),
            client_id: "test_client".to_string(),
            client_secret: None,
            token: SecretString::new("token".to_string()),
            token_type_hint: None,
        };

        let result = client.revoke_token(params);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(100));

        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            assert!(captured_req.auth_header.is_none());
            assert!(captured_req.form_body.contains("client_id=test_client"));
        }
    }

    // ============ Test 23: revoke_token 500 maps to server error ============
    #[test]
    fn test_revoke_token_500_maps_to_server_error() {
        let (port, _captured) = spawn_mock_token_endpoint(500, "Internal Server Error", &[]);

        let client = ReqwestTokenExchangeClient::new();
        let params = RevokeTokenParams {
            revoke_endpoint: format!("http://127.0.0.1:{}/revoke", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            token: SecretString::new("token".to_string()),
            token_type_hint: None,
        };

        let result = client.revoke_token(params);
        assert!(matches!(result, Err(TokenExchangeError::ServerError(500))));
    }

    // ============ Test 24: revoke_token network error maps to network variant ============
    #[test]
    fn test_revoke_token_network_error_maps_to_network_variant() {
        let client = ReqwestTokenExchangeClient::new();
        let params = RevokeTokenParams {
            revoke_endpoint: "http://127.0.0.1:1/revoke".to_string(),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            token: SecretString::new("token_to_revoke".to_string()),
            token_type_hint: None,
        };

        let result = client.revoke_token(params);
        assert!(matches!(result, Err(TokenExchangeError::Network(_))));

        // Verify the error message does NOT contain the secret token
        if let Err(TokenExchangeError::Network(msg)) = result {
            assert!(!msg.contains("token_to_revoke"));
        }
    }

    // ============ Test 25: exchange_code parses scope when present (ADR-021) ============
    #[test]
    fn test_exchange_code_parses_scope_when_present() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","refresh_token":"new_refresh","expires_in":3600,"scope":"offline read:sleep"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.scope, Some("offline read:sleep".to_string()));
    }

    // ============ Test 26: exchange_code scope None when absent (ADR-021) ============
    #[test]
    fn test_exchange_code_scope_none_when_absent() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","refresh_token":"new_refresh","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = ExchangeCodeParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            code: "auth_code".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
        };

        let result = client.exchange_code(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.scope, None);
    }

    // ============ Test 27: refresh_token parses scope when present ============
    #[test]
    fn test_refresh_token_parses_scope_when_present() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600,"scope":"offline"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("old_refresh".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.scope, Some("offline".to_string()));
    }

    // ============ Test 28: refresh_token scope None when absent ============
    #[test]
    fn test_refresh_token_scope_none_when_absent() {
        let (port, _captured) = spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let client = ReqwestTokenExchangeClient::new();
        let params = RefreshTokenParams {
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
            refresh_token: SecretString::new("old_refresh".to_string()),
        };

        let result = client.refresh_token(params);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.scope, None);
    }

    // Helper for slow timeout test
    fn spawn_mock_token_endpoint_slow(delay_ms: u64) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
        let port = listener.local_addr().expect("local_addr").port();

        thread::spawn(move || {
            if let Ok((_stream, _addr)) = listener.accept() {
                // Intentionally sleep without responding
                thread::sleep(Duration::from_millis(delay_ms));
            }
        });

        thread::sleep(Duration::from_millis(50));
        port
    }

}
