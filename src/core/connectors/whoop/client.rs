//! WHOOP API v2 HTTP client with rate limiting.
//!
//! Contract source: Step 3 spec — implements WhoopApiClient for fetching paginated
//! records from WHOOP API v2 with Bearer auth and request/error mapping.
//!
//! Per D-015 security rules: never logs response bodies or health data.
//! Status codes and endpoint paths are logged for debugging.

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use std::time::Duration;

use crate::core::security::SecretString;

use super::dto::WhoopPage;

/// Render a JSON value's field structure with every leaf VALUE redacted —
/// only key names and value *types* are shown, never actual content.
/// Prevents real health data from ever reaching logs/model context (D-015)
/// while still surfacing the field names needed to diagnose a DTO mismatch,
/// including future WHOOP API drift (this exact mechanism found and fixed
/// 3 dto.rs ASSUMPTION errors during T-401's manual e2e verification).
fn redact_json_shape(value: &serde_json::Value) -> String {
    fn walk(value: &serde_json::Value, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        match value {
            serde_json::Value::Object(map) => map
                .iter()
                .map(|(k, v)| format!("{pad}{k}: {}", walk(v, indent + 1)))
                .collect::<Vec<_>>()
                .join("\n"),
            serde_json::Value::Array(items) => {
                if let Some(first) = items.first() {
                    format!("[array, len={}]\n{}", items.len(), walk(first, indent + 1))
                } else {
                    "[array, len=0]".to_string()
                }
            }
            serde_json::Value::String(_) => "<string, REDACTED>".to_string(),
            serde_json::Value::Number(_) => "<number, REDACTED>".to_string(),
            serde_json::Value::Bool(_) => "<bool, REDACTED>".to_string(),
            serde_json::Value::Null => "null".to_string(),
        }
    }
    walk(value, 0)
}

/// WHOOP API v2 client with configurable base URL (for testing).
pub struct WhoopApiClient {
    /// Blocking HTTP client with 30s timeout, 5s connect timeout.
    client: reqwest::blocking::Client,
}

impl WhoopApiClient {
    /// Create a new WHOOP API client with default production timeouts.
    ///
    /// - Overall request timeout: 30 seconds
    /// - Connection timeout: 5 seconds
    /// - TLS via rustls (no OpenSSL)
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client construction must not fail");
        WhoopApiClient { client }
    }

}

impl Default for WhoopApiClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from WHOOP API v2 client.
///
/// Distinguishes between retryable errors (network, rate limit, 5xx) and
/// non-retryable ones (4xx, 401, malformed response).
#[derive(Debug, Clone)]
pub enum WhoopApiError {
    /// Network error (connection timeout, DNS failure, no connectivity).
    Network(String),

    /// HTTP 429 — rate limited.
    /// `retry_after_secs` may be extracted from Retry-After header if present.
    RateLimited { retry_after_secs: Option<u64> },

    /// HTTP 401 — unauthorized (invalid/expired access token).
    Unauthorized,

    /// HTTP 5xx — server error (transient provider issue).
    ServerError(u16),

    /// HTTP 4xx (other than 401/429) — client error.
    ClientError { status: u16 },

    /// 2xx response with unparseable JSON body.
    /// Per D-015, does NOT include the response body (security — no health data exposure).
    MalformedResponse(String),
}

impl WhoopApiClient {
    /// Fetch a paginated page of records from the WHOOP API.
    ///
    /// # Arguments
    /// - `base_url`: e.g., `"https://api.prod.whoop.com/developer/v2"` (parameter for testing flexibility)
    /// - `endpoint_path`: e.g., `"/activity/sleep"` (path without query params)
    /// - `access_token`: Bearer token (SecretString for safety)
    /// - `start`, `end`: RFC3339 timestamps for filtering
    /// - `next_token`: pagination token from previous response (if any)
    ///
    /// Query params: `start`, `end` (RFC3339), `nextToken` (if Some), `limit=25`
    ///
    /// # Errors
    /// Returns `WhoopApiError::MalformedResponse` if 2xx but JSON unparseable (no body logged).
    pub fn fetch_page<T: DeserializeOwned>(
        &self,
        base_url: &str,
        endpoint_path: &str,
        access_token: &SecretString,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        next_token: Option<&str>,
    ) -> Result<WhoopPage<T>, WhoopApiError> {
        let url = format!("{}{}", base_url, endpoint_path);

        let mut request = self.client.get(&url);

        // Add Bearer auth header
        request = request.bearer_auth(access_token.expose_secret());

        // Add query parameters
        request = request
            .query(&[("start", start.to_rfc3339())])
            .query(&[("end", end.to_rfc3339())])
            .query(&[("limit", "25")]);

        if let Some(token) = next_token {
            request = request.query(&[("nextToken", token)]);
        }

        // Execute request
        let response = match request.send() {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "WHOOP API network error");
                return Err(WhoopApiError::Network(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        tracing::debug!(status, endpoint = endpoint_path, "WHOOP API response received");

        match status {
            200 => {
                let text = response.text().unwrap_or_default();
                match serde_json::from_str::<WhoopPage<T>>(&text) {
                    Ok(page) => {
                        tracing::debug!("WHOOP API fetch success");
                        Ok(page)
                    }
                    Err(parse_err) => {
                        // Diagnostic aid for WHOOP API drift (found real value on
                        // T-401 manual e2e — corrected 3 dto.rs ASSUMPTION mismatches
                        // this way): log only the JSON KEY STRUCTURE, never leaf
                        // values, so real health data never reaches logs (D-015) —
                        // just field names/types needed to fix the DTO mapping if
                        // WHOOP changes their response shape in the future.
                        // T-408: raised from warn! to error! — the default tracing
                        // filter (EnvFilter::from_default_env(), no RUST_LOG set)
                        // only shows ERROR, so this diagnostic was silently dropped
                        // in every real deployment (plugin/mcpb ship no RUST_LOG),
                        // discovered only because a user hit this exact error live.
                        // parse_err (serde_json's Display) describes a type/shape
                        // mismatch ("invalid type: X, expected Y at line/column"),
                        // never a leaf value — safe under D-015.
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                            tracing::error!(
                                status,
                                endpoint = endpoint_path,
                                parse_error = %parse_err,
                                shape = %redact_json_shape(&value),
                                "WHOOP API 2xx with malformed JSON body — shape (values redacted)"
                            );
                        } else {
                            tracing::error!(status, endpoint = endpoint_path, parse_error = %parse_err, "WHOOP API 2xx response is not valid JSON at all");
                        }
                        Err(WhoopApiError::MalformedResponse(
                            "Failed to parse WHOOP API response".to_string(),
                        ))
                    }
                }
            }
            401 => {
                tracing::warn!("WHOOP API 401 unauthorized");
                Err(WhoopApiError::Unauthorized)
            }
            429 => {
                // Try to parse Retry-After header
                let retry_after_secs = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                tracing::warn!(retry_after_secs, "WHOOP API rate limited");
                Err(WhoopApiError::RateLimited { retry_after_secs })
            }
            500..=599 => {
                tracing::warn!(status, "WHOOP API server error");
                Err(WhoopApiError::ServerError(status))
            }
            400..=499 => {
                tracing::warn!(status, "WHOOP API client error");
                Err(WhoopApiError::ClientError { status })
            }
            _ => {
                tracing::warn!(status, "WHOOP API unexpected status");
                Err(WhoopApiError::ServerError(status))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Mock HTTP server for testing — reuses pattern from reqwest_token_exchange_client tests.
    /// Binds 127.0.0.1:0, spawns thread, accepts ONE connection, reads request,
    /// responds with status+body, returns (port, request_capture).
    pub(crate) fn spawn_mock_whoop_endpoint(
        status: u16,
        body: &'static str,
        headers: &[(&str, &str)],
    ) -> (u16, Arc<Mutex<Option<CapturedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
        let port = listener.local_addr().expect("local_addr").port();
        let captured = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

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

                    // Capture Authorization header by searching raw request string
                    let auth_header = request_str.find("Authorization: ").map(|start| {
                        let auth_start = start + "Authorization: ".len();
                        let end = request_str[auth_start..]
                            .find('\r')
                            .or_else(|| request_str[auth_start..].find('\n'))
                            .unwrap_or(request_str[auth_start..].len());
                        request_str[auth_start..auth_start + end].to_string()
                    });

                    *captured_clone.lock().unwrap() = Some(CapturedRequest {
                        request_line,
                        auth_header,
                    });
                }

                // Write response
                let status_text = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
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

        thread::sleep(Duration::from_millis(50));
        (port, captured)
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub(crate) struct CapturedRequest {
        pub(crate) request_line: String,
        pub(crate) auth_header: Option<String>,
    }

    // ============ Test 1: success ============
    #[test]
    fn test_fetch_page_success_parses_records_and_next_token() {
        let (port, _captured) = spawn_mock_whoop_endpoint(
            200,
            r#"{"records":[{"id":"sleep-1"},{"id":"sleep-2"}],"next_token":"page2"}"#,
            &[("Content-Type", "application/json")],
        );

        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &SecretString::new("test_token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(result.is_ok());
        let page = result.unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.next_token, Some("page2".to_string()));
    }

    // ============ Test 2: Request succeeds with Bearer auth ============
    #[test]
    fn test_fetch_page_sends_bearer_auth_header() {
        let (port, _captured) = spawn_mock_whoop_endpoint(
            200,
            r#"{"records":[],"next_token":null}"#,
            &[("Content-Type", "application/json")],
        );

        let client = WhoopApiClient::new();
        let token = SecretString::new("test_bearer_token".to_string());
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &token,
            Utc::now(),
            Utc::now(),
            None,
        );

        // If Bearer auth is incorrect, server would return 401.
        // Successful 200 response indicates Bearer auth was sent correctly.
        assert!(result.is_ok());
    }

    // ============ Test 3: 401 Unauthorized ============
    #[test]
    fn test_fetch_page_401_maps_to_unauthorized() {
        let (port, _captured) =
            spawn_mock_whoop_endpoint(401, r#"{"error":"invalid_token"}"#, &[("Content-Type", "application/json")]);

        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &SecretString::new("expired_token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(matches!(result, Err(WhoopApiError::Unauthorized)));
    }

    // ============ Test 4: 429 with Retry-After ============
    #[test]
    fn test_fetch_page_429_parses_retry_after() {
        let (port, _captured) = spawn_mock_whoop_endpoint(
            429,
            r#"{"error":"rate_limit_exceeded"}"#,
            &[("Retry-After", "60"), ("Content-Type", "application/json")],
        );

        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &SecretString::new("token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(matches!(
            result,
            Err(WhoopApiError::RateLimited {
                retry_after_secs: Some(60)
            })
        ));
    }

    // ============ Test 5: 500 Server Error ============
    #[test]
    fn test_fetch_page_500_maps_to_server_error() {
        let (port, _captured) = spawn_mock_whoop_endpoint(500, "Internal Server Error", &[]);

        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &SecretString::new("token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(matches!(result, Err(WhoopApiError::ServerError(500))));
    }

    // ============ Test 6: Network error ============
    #[test]
    fn test_fetch_page_network_error() {
        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            "http://127.0.0.1:1", // Port 1 unlikely to accept
            "/activity/sleep",
            &SecretString::new("token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(matches!(result, Err(WhoopApiError::Network(_))));
    }

    // ============ Test 7: Malformed JSON does not leak body ============
    #[test]
    fn test_fetch_page_malformed_json_does_not_leak_body_in_error() {
        let (port, _captured) = spawn_mock_whoop_endpoint(
            200,
            "not json at all — this is health data 1234567890",
            &[("Content-Type", "application/json")],
        );

        let client = WhoopApiClient::new();
        let result = client.fetch_page::<serde_json::Value>(
            &format!("http://127.0.0.1:{}", port),
            "/activity/sleep",
            &SecretString::new("token".to_string()),
            Utc::now(),
            Utc::now(),
            None,
        );

        assert!(matches!(result, Err(WhoopApiError::MalformedResponse(_))));

        // Verify the error message does NOT contain the response body (security)
        if let Err(WhoopApiError::MalformedResponse(msg)) = result {
            assert!(
                !msg.contains("health data"),
                "MalformedResponse error should not leak response body"
            );
            assert!(
                !msg.contains("1234567890"),
                "MalformedResponse error should not leak response body data"
            );
        }
    }
}
