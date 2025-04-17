use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;
use tracing::error;

///The port where the local server is listening on the auth_code
#[allow(dead_code)]
pub const LOCAL_SERVER_PORT: u16 = 47828;
/// Opens the given URL in the default system browser and starts a local web server
/// to receive the authorization code.
#[allow(dead_code)]
pub async fn open_url(url: &str) -> Option<String> {
    // Try to open the browser using a more reliable approach based on the Python code
    if !try_open_browser(url) {
        tracing::error!("Failed to open browser for URL: {}", url);
        return None;
    }

    // Continue with the existing code to listen for the response
    start_webserver()
}

fn try_open_browser(url: &str) -> bool {
    // First try the platform's default browser opening mechanism
    #[cfg(target_os = "windows")]
    {
        // First try the most reliable Windows method
        match Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
        {
            Ok(_) => return true,
            Err(e) => {
                tracing::warn!("Failed to open browser with rundll32: {}", e);
                // Fall through to try other methods
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // First try xdg-open
        match Command::new("xdg-open").arg(url).spawn() {
            Ok(_) => return true,
            Err(e) => {
                tracing::warn!("Failed to open browser with xdg-open: {}", e);
            }
        }

        // Check if running under WSL
        let is_wsl = std::fs::read_to_string("/proc/version")
            .map(|v| v.to_lowercase().contains("microsoft"))
            .unwrap_or(false);

        if is_wsl {
            // Try the WSL-specific method with PowerShell
            match Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Start-Process \"{}\"", url),
                ])
                .spawn()
            {
                Ok(_) => return true,
                Err(e) => {
                    tracing::error!("Failed to open browser under WSL: {}", e);
                    return false;
                }
            }
        }

        return false;
    }

    #[allow(unreachable_code)]
    true
}

/// starting the browser if the browser could be started, then the webserver should be started to
/// get the auth code
#[allow(dead_code)]
fn handle_browser_command(result: Result<async_process::Child, io::Error>) -> Option<String> {
    match result {
        Ok(_) => start_webserver(),
        Err(e) => {
            error!("Failed to start browser command: {e}");
            None
        }
    }
}

/// Starts the webserver on the `http://localhost`. Returns None, if the server could not have
/// started
#[allow(dead_code)]
/// Starts a simple HTTP server on localhost to receive the auth code.
fn start_webserver() -> Option<String> {
    println!("Waiting for authentication response...");
    
    let listener = TcpListener::bind(("127.0.0.1", LOCAL_SERVER_PORT)).ok()?;
    listener.set_nonblocking(true).ok()?;
    
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(300); // 5-minute timeout
    
    // Progress indicator (optional)
    let mut last_indicator_time = start_time;
    let indicator_interval = std::time::Duration::from_secs(30);
    
    loop {
        if start_time.elapsed() > timeout {
            println!("Authentication timed out after waiting 5 minutes");
            return None;
        }
        
        // Print periodic waiting message
        if last_indicator_time.elapsed() >= indicator_interval {
            println!("Still waiting for authentication response... (press Ctrl+C to cancel)");
            last_indicator_time = std::time::Instant::now();
        }
        
        match listener.accept() {
            Ok((stream, _)) => return handle_client(stream),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                tracing::error!("Error accepting connection: {}", e);
                return None;
            }
        }
    }
}

/// Main method to handle the incomming traffic.
/// After a 10s timeout the stream will be closed
/// if the stream could be opened, we read the whole request and try to extract the auth_code
/// Returns also the html code to show if it worked
#[allow(dead_code)]
fn handle_client(mut stream: TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;

    let buf_reader = BufReader::new(&stream);
    let mut request_lines = vec![];
    for line in buf_reader.lines().map_while(Result::ok) {
        if line.is_empty() {
            break;
        }
        request_lines.push(line);
    }

    let request = request_lines.join("\n");

    let auth_code = extract_auth_code(&request);
    let response_body = r#"<!DOCTYPE html>
<html><head><title>Auth Complete</title></head>
<body><p>Authentication complete. You may close this tab.</p></body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    stream.write_all(response.as_bytes()).ok()?;
    stream.flush().ok()?;
    stream.shutdown(Shutdown::Both).ok()?;

    auth_code
}

/// Extracts the `code` query parameter from the request.
#[allow(dead_code)]
fn extract_auth_code(request: &str) -> Option<String> {
    let code_start = request.rfind("code=")? + 5;
    let rest = &request[code_start..];
    let end = rest.find('&').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

// Add this new function for tests
#[allow(dead_code)]
async fn is_command_available(cmd: &str) -> bool {
    #[cfg(windows)]
    let result = Command::new("where").arg(cmd).output();
    #[cfg(not(windows))]
    let result = Command::new("which").arg(cmd).output();

    match result {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod test_internal_server {
    use super::*;
    use tracing::debug;
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;
    fn init_logger() {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[tokio::test]
    async fn test_valid_command() {
        init_logger();
        assert!(is_command_available("ls").await);
    }

    #[tokio::test]
    async fn test_invalid_command() {
        init_logger();
        assert!(!is_command_available("non_existing_command_foo").await);
    }

    #[test]
    fn test_extract_code_param() {
        let url = "GET /?code=abc123&state=xyz";
        assert_eq!(extract_auth_code(url).unwrap(), "abc123");
    }

    #[test]
    fn test_extract_code_at_end() {
        let url = "GET /?state=xyz&code=abc123";
        assert_eq!(extract_auth_code(url).unwrap(), "abc123");
    }

    #[test]
    fn test_extract_code_missing() {
        let url = "GET /?state=only";
        assert!(extract_auth_code(url).is_none());
    }
}
