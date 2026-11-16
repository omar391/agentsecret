use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const CAPABILITY: &str = "aspc1.test.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct CapabilityFile {
    path: PathBuf,
}

impl CapabilityFile {
    fn new(contents: &str, mode: u32) -> Self {
        let path = std::env::temp_dir().join(format!(
            "agentsecret-mcp-capability-{}-{}.txt",
            std::process::id(),
            NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, contents).expect("write capability file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set capability file mode");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CapabilityFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn supervisor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
}

fn run_with(mut command: Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MCP supervisor");
    let mut input = input.to_owned();
    if !input.ends_with('\n') {
        input.push('\n');
    }
    child
        .stdin
        .take()
        .expect("open MCP stdin")
        .write_all(input.as_bytes())
        .expect("write MCP request");
    child.wait_with_output().expect("wait for MCP supervisor")
}

fn mcp_command(capability_file: &Path) -> Command {
    let mut command = supervisor();
    command.args([
        "mcp",
        "--self",
        env!("CARGO_BIN_EXE_agentsecret-supervisor"),
        "--broker-origin",
        "https://127.0.0.1:8443",
        "--capability-file",
    ]);
    command.arg(capability_file);
    command
}

fn exchange(capability_file: &Path, input: &str) -> Output {
    run_with(mcp_command(capability_file), input)
}

#[test]
fn mcp_server_advertises_only_the_exact_proxy_tool() {
    let capability = CapabilityFile::new(CAPABILITY, 0o600);
    let output = exchange(
        capability.path(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let mut lines = stdout.lines();
    let initialize: serde_json::Value =
        serde_json::from_str(lines.next().expect("initialize response")).expect("initialize JSON");
    let tools: serde_json::Value =
        serde_json::from_str(lines.next().expect("tools response")).expect("tools JSON");
    assert_eq!(
        initialize["result"]["serverInfo"]["name"],
        "agentsecret-supervisor"
    );
    let tools = tools["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "proxy_http_request");
    assert_eq!(tools[0]["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        tools[0]["inputSchema"]["required"],
        serde_json::json!(["secret_alias", "url", "method"])
    );
}

#[test]
fn mcp_server_rejects_unknown_tools_without_invoking_the_gateway() {
    let capability = CapabilityFile::new(CAPABILITY, 0o600);
    let output = exchange(
        capability.path(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"shell\",\"arguments\":{}}}\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(response["error"]["message"], "unknown_tool");
}

#[test]
fn mcp_server_rejects_missing_required_call_arguments_before_gateway_dispatch() {
    let capability = CapabilityFile::new(CAPABILITY, 0o600);
    let output = exchange(
        capability.path(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"proxy_http_request\",\"arguments\":{\"secret_alias\":\"TEST\"}}}\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(response["error"]["message"], "gateway_request_invalid");
}

#[test]
fn mcp_server_refuses_a_capability_passed_in_process_arguments() {
    let output = run_with(
        {
            let mut command = supervisor();
            command.args([
                "mcp",
                "--self",
                env!("CARGO_BIN_EXE_agentsecret-supervisor"),
                "--broker-origin",
                "https://127.0.0.1:8443",
                "--capability",
                CAPABILITY,
            ]);
            command
        },
        "",
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "invalid_arguments"
    );
}

#[test]
fn mcp_server_requires_a_private_capability_file() {
    let output = run_with(
        mcp_command(Path::new("/nonexistent/agentsecret-capability")),
        "",
    );
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "capability_file_unavailable"
    );

    let capability = CapabilityFile::new(CAPABILITY, 0o644);
    let output = run_with(mcp_command(capability.path()), "");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "capability_file_permissions"
    );

    let capability = CapabilityFile::new("not-a-proxy-capability", 0o600);
    let output = run_with(mcp_command(capability.path()), "");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "capability_file_invalid"
    );
}

#[test]
fn mcp_gateway_child_receives_the_capability_file_path_and_never_the_capability() {
    let capability = CapabilityFile::new(CAPABILITY, 0o600);
    let recorder = ArgRecorder::new();
    let mut command = supervisor();
    command.args([
        "mcp",
        "--self",
        recorder.script_path().to_str().expect("UTF-8 script path"),
        "--broker-origin",
        "https://127.0.0.1:8443",
        "--capability-file",
    ]);
    command.arg(capability.path());
    let output = run_with(
        command,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"proxy_http_request\",\"arguments\":{\"secret_alias\":\"TEST\",\"url\":\"https://example.test/\",\"method\":\"GET\"}}}\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("gateway call JSON");
    assert_eq!(response["error"]["message"], "gateway_execution_failed");

    let observed = recorder.arguments();
    assert_eq!(
        observed,
        [
            "gateway",
            "--broker-origin",
            "https://127.0.0.1:8443",
            "--capability-file",
            capability.path().to_str().expect("UTF-8 capability path"),
        ]
    );
    assert!(
        !observed
            .iter()
            .any(|argument| argument.contains(CAPABILITY))
    );
}

struct ArgRecorder {
    script: PathBuf,
    arguments_file: PathBuf,
}

impl ArgRecorder {
    fn new() -> Self {
        let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let script = std::env::temp_dir().join(format!(
            "agentsecret-mcp-argv-recorder-{}-{id}.sh",
            std::process::id()
        ));
        let arguments_file = std::env::temp_dir().join(format!(
            "agentsecret-mcp-argv-record-{}-{id}.txt",
            std::process::id()
        ));
        let arguments_path = arguments_file.display().to_string();
        let script_contents = format!(
            "#!/bin/sh\n: > '{arguments_path}'\nfor argument in \"$@\"; do printf '%s\\n' \"$argument\" >> '{arguments_path}'; done\nexit 1\n"
        );
        fs::write(&script, script_contents).expect("write recorder script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .expect("make recorder executable");
        Self {
            script,
            arguments_file,
        }
    }

    fn script_path(&self) -> &Path {
        &self.script
    }

    fn arguments(&self) -> Vec<String> {
        fs::read_to_string(&self.arguments_file)
            .expect("read recorded arguments")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for ArgRecorder {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.script);
        let _ = fs::remove_file(&self.arguments_file);
    }
}
