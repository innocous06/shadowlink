//! # Probe Resistance
//!
//! When unauthorized clients (DPI probers, port scanners, etc.) connect,
//! the server serves a decoy website instead of revealing that it's a proxy.
//!
//! ## How it works:
//! 1. Every connection starts with the TLS handshake (normal HTTPS)
//! 2. Server attempts the ShadowLink handshake
//! 3. If the handshake fails (wrong key, no key, random prober):
//!    - Server serves a static HTML page as if it were a normal web server
//!    - The prober sees a regular website, not a proxy
//! 4. nmap, censorship scanners, etc. see a normal HTTPS site
//!
//! ## What the decoy looks like:
//! A simple, generic business/blog website. Can be customized.

use anyhow::Result;

/// Default decoy HTML page served to unauthorized connections.
/// Looks like a generic website — nothing suspicious.
pub const DEFAULT_DECOY_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudSync Solutions</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               background: #f8f9fa; color: #333; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   padding: 80px 20px; text-align: center; color: white; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.2rem; opacity: 0.9; }
        .content { max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; padding: 30px;
                margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .footer { text-align: center; padding: 40px; color: #999; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CloudSync Solutions</h1>
        <p>Enterprise Cloud Infrastructure Management</p>
    </div>
    <div class="content">
        <div class="card">
            <h2>About Us</h2>
            <p>CloudSync Solutions provides enterprise-grade cloud infrastructure management, 
               helping businesses optimize their cloud deployments across multiple providers.</p>
        </div>
        <div class="card">
            <h2>Our Services</h2>
            <p>Multi-cloud orchestration, infrastructure monitoring, cost optimization, 
               and 24/7 managed services for businesses of all sizes.</p>
        </div>
        <div class="card">
            <h2>Contact</h2>
            <p>For inquiries, please reach out to our sales team.</p>
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2025 CloudSync Solutions. All rights reserved.</p>
    </div>
</body>
</html>"#;

/// HTTP response headers for the decoy page
fn build_http_response(body: &str) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Server: nginx/1.24.0\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n\
         \r\n",
        body.len()
    );

    let mut response = Vec::with_capacity(headers.len() + body.len());
    response.extend_from_slice(headers.as_bytes());
    response.extend_from_slice(body.as_bytes());
    response
}

/// Build a 404 response for unknown paths
fn build_404_response() -> Vec<u8> {
    let body = "<html><body><h1>404 Not Found</h1></body></html>";
    let headers = format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Server: nginx/1.24.0\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    let mut response = Vec::with_capacity(headers.len() + body.len());
    response.extend_from_slice(headers.as_bytes());
    response.extend_from_slice(body.as_bytes());
    response
}

/// Probe resistance handler.
///
/// When a connection fails the ShadowLink handshake, this handler
/// takes over and serves a decoy website.
pub struct ProbeResistHandler {
    /// The HTML content to serve as a decoy
    decoy_html: String,
    /// Pre-built HTTP response bytes
    response_bytes: Vec<u8>,
    /// Pre-built 404 response bytes
    not_found_bytes: Vec<u8>,
}

impl ProbeResistHandler {
    /// Create a new probe resistance handler with the default decoy page.
    pub fn new() -> Self {
        Self::with_custom_html(DEFAULT_DECOY_HTML.to_string())
    }

    /// Create a new probe resistance handler with custom decoy HTML.
    pub fn with_custom_html(html: String) -> Self {
        let response_bytes = build_http_response(&html);
        let not_found_bytes = build_404_response();
        Self {
            decoy_html: html,
            response_bytes,
            not_found_bytes,
        }
    }

    /// Serve the decoy page to an unauthorized connection.
    ///
    /// Reads the initial bytes from the stream to determine if it's an HTTP request,
    /// then responds appropriately.
    pub async fn serve_decoy<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Try to read what the client sent (likely an HTTP request from a browser/scanner)
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                // Timeout or error — just serve the default page and close
                let _ = stream.write_all(&self.response_bytes).await;
                return Ok(());
            }
        };

        let request = String::from_utf8_lossy(&buf[..n]);

        // Check if it looks like an HTTP GET request
        if request.starts_with("GET / ") || request.starts_with("GET /index") {
            stream.write_all(&self.response_bytes).await?;
        } else if request.starts_with("GET ") || request.starts_with("HEAD ") {
            // Any other path → 404
            stream.write_all(&self.not_found_bytes).await?;
        } else {
            // Not HTTP at all — just close
            stream.write_all(&self.response_bytes).await?;
        }

        Ok(())
    }

    /// Get the decoy HTML content
    pub fn decoy_html(&self) -> &str {
        &self.decoy_html
    }
}

impl Default for ProbeResistHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_decoy_is_valid_html() {
        assert!(DEFAULT_DECOY_HTML.contains("<!DOCTYPE html>"));
        assert!(DEFAULT_DECOY_HTML.contains("</html>"));
        // Should not contain anything suspicious
        assert!(!DEFAULT_DECOY_HTML.to_lowercase().contains("proxy"));
        assert!(!DEFAULT_DECOY_HTML.to_lowercase().contains("vpn"));
        assert!(!DEFAULT_DECOY_HTML.to_lowercase().contains("tunnel"));
        assert!(!DEFAULT_DECOY_HTML.to_lowercase().contains("shadowlink"));
    }

    #[test]
    fn test_http_response_format() {
        let response = build_http_response("Hello");
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Length: 5"));
        assert!(response_str.contains("nginx")); // Mimics nginx
        assert!(response_str.ends_with("Hello"));
    }

    #[test]
    fn test_custom_decoy() {
        let custom = "<html><body>Custom Site</body></html>".to_string();
        let handler = ProbeResistHandler::with_custom_html(custom.clone());
        assert_eq!(handler.decoy_html(), custom);
    }

    #[tokio::test]
    async fn test_serve_decoy_to_http_request() {
        let handler = ProbeResistHandler::new();
        let (mut client, mut server) = tokio::io::duplex(65536);

        // Simulate an HTTP GET request from a scanner
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let client_handle = tokio::spawn(async move {
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();

            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            response
        });

        handler.serve_decoy(&mut server).await.unwrap();
        drop(server);

        let response = client_handle.await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("CloudSync Solutions"));
    }
}
