//! macOS OAuth callback handler (родительские T-202, T-006 Adapter 2).
//!
//! Implementation: `open_system_browser` launches the system browser via `open` command.
//! `listen_for_callback` starts a temporary localhost HTTP listener on 127.0.0.1
//! to receive OAuth redirects (T-301).

use crate::adapters::{CallbackError, CallbackReceiver, CallbackResult, OAuthCallbackHandler};
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// macOS-specific OAuth callback handler implementation (T-202, T-201 composition-root pattern).
///
/// Uses `open` command to launch the system browser. Callback delivery will be
/// implemented as a temporary localhost loopback listener (EPIC-03, T-301) —
/// в MCP-форм-факторе deep-link/Info.plist не нужны, редирект принимает
/// локальный HTTP-listener на 127.0.0.1.
#[derive(Debug, Clone)]
pub struct MacOSOAuthCallbackHandler;

impl MacOSOAuthCallbackHandler {
    /// Construct a new macOS OAuth callback handler.
    ///
    /// Stateless — all state is managed by the caller and macOS system.
    pub fn new() -> Self {
        MacOSOAuthCallbackHandler
    }
}

impl Default for MacOSOAuthCallbackHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthCallbackHandler for MacOSOAuthCallbackHandler {
    fn listen_for_callback(&self, expected_state: &str) -> Result<CallbackReceiver, CallbackError> {
        // dev-only manual e2e hook (T-401); unset in production/tests → dynamic port, T-301 unaffected
        let port = std::env::var("VITALSTEAD_OAUTH_FIXED_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        // Bind to a temporary TCP listener on 127.0.0.1 with OS-assigned port or fixed dev port
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", port))
            .map_err(|_| CallbackError::ListenerBindFailed)?;
        std_listener.set_nonblocking(true)
            .map_err(|_| CallbackError::ListenerBindFailed)?;
        let port = std_listener.local_addr()
            .map_err(|_| CallbackError::ListenerBindFailed)?
            .port();

        // Convert to tokio listener
        let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|_| CallbackError::ListenerBindFailed)?;

        // Create oneshot channel for callback result
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackResult, CallbackError>>();
        let expected_state = expected_state.to_string();

        // Spawn listener task
        tokio::spawn(run_listener(
            tokio_listener,
            expected_state,
            tx,
            crate::core::oauth::AUTHORIZATION_TIMEOUT,
        ));

        tracing::info!(port, "OAuth callback listener bound");

        Ok(CallbackReceiver { recv: rx, port })
    }

    fn open_system_browser(&self, url: &str) -> Result<(), CallbackError> {
        // Security: reject non-https URLs (file://, javascript:, etc.)
        if !url.starts_with("https://") {
            return Err(CallbackError::BrowserLaunchFailed);
        }

        // Launch macOS system browser via `open` command
        match Command::new("open").arg(url).status() {
            Ok(status) => {
                if status.success() {
                    Ok(())
                } else {
                    Err(CallbackError::BrowserLaunchFailed)
                }
            }
            Err(_) => Err(CallbackError::BrowserLaunchFailed),
        }
    }
}

// HTML responses (no query parameter substitution — static only)
const SUCCESS_HTML: &str = "<!doctype html><html><body><p>Authorization complete. You can close this tab and return to Claude.</p></body></html>";
const REJECTED_HTML: &str = "<!doctype html><html><body><p>This authorization link is invalid or expired. You can close this tab.</p></body></html>";
const GENERIC_HTML: &str = "<!doctype html><html><body><p>You can close this tab.</p></body></html>";

/// Listener task that accepts HTTP requests and delivers results via oneshot channel.
/// Parametrized with timeout for testability.
pub(crate) async fn run_listener(
    listener: tokio::net::TcpListener,
    expected_state: String,
    tx: tokio::sync::oneshot::Sender<Result<CallbackResult, CallbackError>>,
    timeout: std::time::Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            let _ = tx.send(Err(CallbackError::Timeout));
            return;
        }

        let accept_result = tokio::time::timeout(remaining, listener.accept()).await;
        let (stream, _peer) = match accept_result {
            Err(_elapsed) => {
                let _ = tx.send(Err(CallbackError::Timeout));
                return;
            }
            Ok(Err(_io_err)) => continue, // transient accept() error — continue waiting
            Ok(Ok(pair)) => pair,
        };

        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handle_connection(stream, &expected_state),
        ).await {
            Ok(ConnectionOutcome::Delivered(result)) => {
                let _ = tx.send(Ok(result));
                return; // single-shot: exit only after valid callback
            }
            Ok(ConnectionOutcome::Rejected) => continue,
            Err(_read_timeout) => continue,
        }
    }
}

/// Outcome of handling a single HTTP connection.
enum ConnectionOutcome {
    Delivered(CallbackResult),
    Rejected,
}

/// Parse and handle a single HTTP connection.
async fn handle_connection(mut stream: tokio::net::TcpStream, expected_state: &str) -> ConnectionOutcome {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return ConnectionOutcome::Rejected,
    };

    let request_line = match std::str::from_utf8(&buf[..n]).ok().and_then(|s| s.lines().next()) {
        Some(line) => line,
        None => { let _ = respond(&mut stream, 400, GENERIC_HTML).await; return ConnectionOutcome::Rejected; }
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "GET" { let _ = respond(&mut stream, 405, GENERIC_HTML).await; return ConnectionOutcome::Rejected; }

    let (path, query) = match target.split_once('?') { Some((p, q)) => (p, q), None => (target, "") };

    if path != "/callback" { let _ = respond(&mut stream, 404, GENERIC_HTML).await; return ConnectionOutcome::Rejected; }

    let params = parse_query(query);
    let get = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());

    let state = get("state");
    let state_ok = matches!(&state, Some(s) if s == expected_state);

    if !state_ok {
        let _ = respond(&mut stream, 400, REJECTED_HTML).await;
        tracing::warn!("OAuth callback rejected: state mismatch or missing");
        return ConnectionOutcome::Rejected;
    }

    if let Some(error) = get("error") {
        let _ = respond(&mut stream, 200, SUCCESS_HTML).await;
        return ConnectionOutcome::Delivered(CallbackResult::Error { error, error_description: get("error_description") });
    }

    match get("code") {
        Some(code) => {
            let _ = respond(&mut stream, 200, SUCCESS_HTML).await;
            tracing::info!("OAuth callback received: valid state, delivering result");
            ConnectionOutcome::Delivered(CallbackResult::Success { code, state: state.unwrap() })
        }
        None => { let _ = respond(&mut stream, 400, GENERIC_HTML).await; ConnectionOutcome::Rejected }
    }
}

/// Send HTTP response.
async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let status_text = match status { 200 => "OK", 400 => "Bad Request", 404 => "Not Found", 405 => "Method Not Allowed", _ => "Error" };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Parse application/x-www-form-urlencoded query string.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query.split('&').filter(|pair| !pair.is_empty()).map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(k), percent_decode(v))
    }).collect()
}

/// Percent-decode a string (RFC 3986 unreserved + reserved characters).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T12: open_system_browser rejects non-https URLs.
    ///
    /// Call with "file:///etc/passwd" or "javascript:alert(1)" → Err(BrowserLaunchFailed),
    /// must be hermetic (scheme check short-circuits before Command::new runs).
    #[test]
    fn test_open_system_browser_rejects_non_https_url() {
        let handler = MacOSOAuthCallbackHandler::new();

        // Test file:// URL
        let result = handler.open_system_browser("file:///etc/passwd");
        assert!(matches!(result, Err(CallbackError::BrowserLaunchFailed)));

        // Test javascript: URL
        let result = handler.open_system_browser("javascript:alert(1)");
        assert!(matches!(result, Err(CallbackError::BrowserLaunchFailed)));

        // Test http:// (not https://)
        let result = handler.open_system_browser("http://example.com");
        assert!(matches!(result, Err(CallbackError::BrowserLaunchFailed)));

        // Test data: URL
        let result = handler.open_system_browser("data:text/html,<h1>test</h1>");
        assert!(matches!(result, Err(CallbackError::BrowserLaunchFailed)));
    }

    /// T1: listen_for_callback binds free port and returns redirect port.
    #[tokio::test]
    async fn test_listen_for_callback_binds_free_port_and_returns_redirect_port() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        assert_ne!(receiver.port, 0);
    }

    /// T2: valid callback success delivers code and state.
    #[tokio::test]
    async fn test_valid_callback_success_delivers_code_and_state() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        // Connect and send valid callback
        let addr = format!("127.0.0.1:{}", port);
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client.write_all(b"GET /callback?code=abc&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();

        // Read response
        let mut response = vec![0u8; 1024];
        let _n = client.read(&mut response).await.unwrap();

        // Await callback result
        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Success { code, state }) = result {
            assert_eq!(code, "abc");
            assert_eq!(state, "state123");
        } else {
            panic!("Expected Success variant");
        }
    }

    /// T3: valid callback error delivers provider error.
    #[tokio::test]
    async fn test_valid_callback_error_delivers_provider_error() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        let addr = format!("127.0.0.1:{}", port);
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client.write_all(b"GET /callback?error=access_denied&error_description=user+said+no&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();

        let mut response = vec![0u8; 1024];
        let _n = client.read(&mut response).await.unwrap();

        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Error { error, error_description }) = result {
            assert_eq!(error, "access_denied");
            // Verify '+' is NOT decoded to space (URI query component, not form-urlencoded)
            assert_eq!(error_description.as_ref().unwrap(), "user+said+no");
        } else {
            panic!("Expected Error variant");
        }
    }

    /// T4: missing state rejected does not terminate listener.
    #[tokio::test]
    async fn test_missing_state_rejected_does_not_terminate_listener() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        // First request: no state → rejected, listener continues
        let addr = format!("127.0.0.1:{}", port);
        let mut client1 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client1.write_all(b"GET /callback?code=xxx HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client1.flush().await.unwrap();
        let mut response = vec![0u8; 1024];
        let _n = client1.read(&mut response).await.unwrap();
        drop(client1);

        // Brief delay for listener to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second request: valid state → accepted
        let mut client2 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client2.write_all(b"GET /callback?code=abc&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client2.flush().await.unwrap();
        let _n = client2.read(&mut response).await.unwrap();

        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Success { code, .. }) = result {
            assert_eq!(code, "abc");
        } else {
            panic!("Expected Success variant");
        }
    }

    /// T5: wrong state rejected does not terminate listener.
    #[tokio::test]
    async fn test_wrong_state_rejected_does_not_terminate_listener() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        let addr = format!("127.0.0.1:{}", port);
        let mut client1 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client1.write_all(b"GET /callback?code=xxx&state=wrong_state HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client1.flush().await.unwrap();
        let mut response = vec![0u8; 1024];
        let _n = client1.read(&mut response).await.unwrap();
        drop(client1);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client2 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client2.write_all(b"GET /callback?code=abc&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client2.flush().await.unwrap();
        let _n = client2.read(&mut response).await.unwrap();

        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Success { code, .. }) = result {
            assert_eq!(code, "abc");
        } else {
            panic!("Expected Success variant");
        }
    }

    /// T6: malformed request without code or error rejected but listener continues.
    #[tokio::test]
    async fn test_malformed_request_without_code_or_error_rejected_but_listener_continues() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        let addr = format!("127.0.0.1:{}", port);
        let mut client1 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client1.write_all(b"GET /callback?state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client1.flush().await.unwrap();
        let mut response = vec![0u8; 1024];
        let _n = client1.read(&mut response).await.unwrap();
        drop(client1);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client2 = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client2.write_all(b"GET /callback?code=abc&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client2.flush().await.unwrap();
        let _n = client2.read(&mut response).await.unwrap();

        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Success { code, .. }) = result {
            assert_eq!(code, "abc");
        } else {
            panic!("Expected Success variant");
        }
    }

    /// T7: HTML response does not reflect query parameters.
    #[tokio::test]
    async fn test_html_response_does_not_reflect_query_parameters() {
        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        let port = receiver.port;

        let addr = format!("127.0.0.1:{}", port);
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        client.write_all(b"GET /callback?code=SECRET_MARKER_XYZ&state=state123 HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();

        let mut response = vec![0u8; 4096];
        let n = client.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..n]);

        assert!(!response_str.contains("SECRET_MARKER_XYZ"), "Response should not contain code parameter");

        // Test with XSS attempt in state
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let result = receiver.recv.await.unwrap();
        assert!(result.is_ok());
        if let Ok(CallbackResult::Success { code, .. }) = result {
            assert_eq!(code, "SECRET_MARKER_XYZ");
        }
    }

    /// T8: timeout when no callback received.
    #[tokio::test]
    async fn test_timeout_when_no_callback_received() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackResult, CallbackError>>();

        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let tokio_listener = tokio::net::TcpListener::from_std(std_listener).unwrap();

        tokio::spawn(run_listener(
            tokio_listener,
            "state123".to_string(),
            tx,
            std::time::Duration::from_millis(200),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let result = rx.await.unwrap();
        assert!(matches!(result, Err(CallbackError::Timeout)));
    }

    /// T13: default port still dynamic without env var (T-401 dev-hook).
    ///
    /// Verifies that VITALSTEAD_OAUTH_FIXED_PORT env var is optional —
    /// when unset, behavior remains unchanged from T-301 (port 0 → OS-assigned).
    #[tokio::test]
    async fn test_default_port_still_dynamic_without_env_var() {
        // Ensure env var is not set
        std::env::remove_var("VITALSTEAD_OAUTH_FIXED_PORT");

        let handler = MacOSOAuthCallbackHandler::new();
        let result = handler.listen_for_callback("state123");
        assert!(result.is_ok());
        let receiver = result.unwrap();
        // Port should be non-zero (OS-assigned), not the fixed dev port
        assert_ne!(receiver.port, 0);
        // Port should be a reasonable number, not accidentally the env var default
        assert!(receiver.port > 1024, "Port should be > 1024");
    }
}
