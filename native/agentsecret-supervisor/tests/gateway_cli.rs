use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

fn start_stub_broker(
    mut handle_request: impl FnMut(&[u8], &str) -> (u16, Vec<u8>) + Send + 'static,
) -> StubBroker {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind broker");
    let address = format!("http://{}/", listener.local_addr().expect("broker address"));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let mut buffer = Vec::new();
            let mut temp = [0u8; 4096];
            let mut content_length = 0usize;
            let mut header_end = None;
            loop {
                match stream.read(&mut temp) {
                    Ok(0) => break,
                    Ok(count) => {
                        buffer.extend_from_slice(&temp[..count]);
                        if header_end.is_none() {
                            if let Some(offset) =
                                buffer.windows(4).position(|window| window == b"\r\n\r\n")
                            {
                                header_end = Some(offset + 4);
                                let headers =
                                    String::from_utf8_lossy(&buffer[..offset]).to_string();
                                content_length = headers
                                    .lines()
                                    .find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.trim()
                                            .eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().ok())
                                            .flatten()
                                    })
                                    .unwrap_or(0);
                            }
                        }
                        if let Some(start) = header_end {
                            if buffer.len() >= start + content_length {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&buffer).to_string();
            let Some(split) = text.split_once("\r\n\r\n") else {
                break;
            };
            let (headers, body) = split;
            let authorization = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            let (status, response) = handle_request(body.as_bytes(), &authorization);
            let reason = match status {
                200 => "OK",
                302 => "Found",
                401 => "Unauthorized",
                409 => "Conflict",
                413 => "Payload Too Large",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&response);
        }
    });
    StubBroker { address }
}

struct StubBroker {
    address: String,
}

fn run_gateway(broker: &str, capability: &str, input: &[u8]) -> std::process::Output {
    let path = write_capability_file(capability, 0o600);
    let output = spawn_gateway(broker, &path, input);
    let _ = std::fs::remove_file(&path);
    output
}

static NEXT_FILE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_capability_file(contents: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "agentsecret-gateway-capability-{}-{}.txt",
        std::process::id(),
        NEXT_FILE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("write capability file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("set capability file mode");
    path
}

fn spawn_gateway(
    broker: &str,
    capability_file: &std::path::Path,
    input: &[u8],
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args(["gateway", "--broker-origin"])
        .arg(broker)
        .args(["--capability-file"])
        .arg(capability_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("AGENTSECRET_GATEWAY_TESTING_ORIGIN", "1")
        .spawn()
        .expect("start gateway supervisor");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(input)
        .expect("write gateway request");
    child.wait_with_output().expect("wait for gateway")
}

fn valid_input() -> Vec<u8> {
    json!({
        "alias": "GitHub_Token",
        "url": "https://api.github.com/repos/example/example",
        "method": "GET",
        "headers": {"accept": "application/vnd.github+json"}
    })
    .to_string()
    .into_bytes()
}

#[test]
fn gateway_refuses_symlinked_and_oversized_capability_files() {
    use std::os::unix::fs::symlink;
    let path = write_capability_file("synthetic-sensitive-capability", 0o600);
    let link = path.with_extension("symlink");
    symlink(&path, &link).expect("create synthetic symlink");
    let linked = spawn_gateway("http://127.0.0.1:9", &link, &valid_input());
    assert!(!linked.status.success());
    assert!(linked.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&linked.stderr).trim(),
        "capability_file_invalid"
    );
    std::fs::remove_file(&link).expect("remove symlink");
    std::fs::write(&path, vec![b'x'; 513]).expect("write oversized capability fixture");
    let oversized = spawn_gateway("http://127.0.0.1:9", &path, &valid_input());
    assert!(!oversized.status.success());
    assert!(oversized.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&oversized.stderr).trim(),
        "capability_file_invalid"
    );
    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn gateway_refuses_a_capability_fifo_without_blocking_for_a_writer() {
    use std::time::{Duration, Instant};
    let path = write_capability_file("unused", 0o600);
    std::fs::remove_file(&path).expect("replace fixture");
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .expect("create FIFO fixture")
            .success()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args([
            "gateway",
            "--broker-origin",
            "https://broker.example.invalid",
            "--capability-file",
        ])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn FIFO probe");
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().expect("poll FIFO probe").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("stop blocked probe");
            let _ = child.wait();
            let _ = std::fs::remove_file(&path);
            panic!("capability FIFO read blocked");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect FIFO refusal");
    std::fs::remove_file(path).expect("remove FIFO fixture");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "capability_file_invalid"
    );
}

#[test]
fn gateway_rejects_unsafe_broker_origin_and_invalid_capability() {
    let output = run_gateway(
        "http://127.0.0.1:9",
        "aspc1.tenant.capability",
        &valid_input(),
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "gateway_request_invalid"
    );

    let output = run_gateway(
        "invalid-capability-format",
        "aspc1.tenant.capability",
        &valid_input(),
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "gateway_request_unsafe"
    );
}

#[test]
fn gateway_requires_a_private_capability_file() {
    let output = spawn_gateway(
        "http://localhost",
        std::path::Path::new("/nonexistent/capability"),
        &valid_input(),
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "capability_file_unavailable"
    );

    let path = write_capability_file("aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345", 0o644);
    let output = spawn_gateway("http://localhost", &path, &valid_input());
    let _ = std::fs::remove_file(&path);
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "capability_file_permissions"
    );
}

#[test]
fn gateway_bounded_input_fails_before_transport() {
    let output = run_gateway(
        "http://localhost",
        "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
        &vec![b' '; 4097],
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "gateway_request_too_large"
    );
}

#[test]
fn gateway_refuses_secret_smuggling_and_local_companion_fallback() {
    let mut input = serde_json::from_str::<Value>(&String::from_utf8(valid_input()).unwrap())
        .expect("valid input object");
    input["secret"] = json!("must-not-be-accepted");
    let output = run_gateway(
        "http://localhost",
        "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
        &input.to_string().into_bytes(),
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "gateway_request_invalid_json"
    );

    let mut input = serde_json::from_str::<Value>(&String::from_utf8(valid_input()).unwrap())
        .expect("valid input object");
    input["method"] = json!("POST");
    input["headers"] = json!({"content-type": "application/json"});
    input["body"] = json!("{\"credential\":\"real-secret\"}");
    let output = run_gateway(
        "http://localhost",
        "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
        &input.to_string().into_bytes(),
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "gateway_request_invalid"
    );
}

#[test]
fn gateway_redacts_response_headers_and_stops_after_one_attempt() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_calls = calls.clone();
    let broker = start_stub_broker(move |_body, authorization| {
        thread_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(authorization.starts_with("AgentSecret aspc1."));
        (
            200,
            br#"{"status":200,"headers":{"set-cookie":"session=not-returned"},"data":{"ok":true}}"#
                .to_vec(),
        )
    });
    let output = run_gateway(
        broker.address.as_str(),
        "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
        &valid_input(),
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["status"], 200);
    assert_eq!(receipt["outcome"], "known");
    assert_eq!(receipt["data"], json!({"ok": true}));
    assert!(receipt.get("headers").is_none());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn gateway_terminal_redirect_and_unknown_outcome_never_retry() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_calls = calls.clone();
    let broker = start_stub_broker(move |_body, _authorization| {
        let count = thread_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if count == 0 {
            (
                200,
                br#"{"status":302,"redirectBlocked":true,"data":null}"#.to_vec(),
            )
        } else {
            (500, br#"{"status":500,"resultStatus":"unknown"}"#.to_vec())
        }
    });
    let output = run_gateway(
        broker.address.as_str(),
        "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
        &valid_input(),
    );
    assert!(output.status.success());
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["status"], 302);
    assert_eq!(receipt["outcome"], "known");
    assert!(receipt.get("data").is_none());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
