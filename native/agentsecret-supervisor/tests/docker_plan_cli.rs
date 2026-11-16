use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentsecret-docker-plan-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_docker_plan(
    root: &Path,
    scratch: &Path,
    sandbox_name: &str,
    request: &Value,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args(["docker-plan", "--host-root"])
        .arg(root)
        .arg("--scratch")
        .arg(scratch)
        .arg("--sandbox-name")
        .arg(sandbox_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start docker-plan supervisor");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(request.to_string().as_bytes())
        .expect("write synthetic request");
    child
        .wait_with_output()
        .expect("wait for docker-plan supervisor")
}

fn project_root(temp: &TestDir) -> PathBuf {
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::canonicalize(&root).unwrap()
}

fn base_request() -> Value {
    json!({
        "version": 1,
        "executable": "/usr/bin/curl",
        "argv": ["--silent", "--show-error", "https://api.example.com/v1/status"],
        "working_directory": "/workspace/project"
    })
}

#[test]
fn docker_plan_cli_emits_full_command_plan_and_stages_files() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let source = root.join("config.txt");
    fs::write(&source, b"synthetic-test-value").unwrap();
    let source_nested = root.join("nested");
    fs::create_dir(&source_nested).unwrap();
    let nested_file = source_nested.join("data.bin");
    fs::write(&nested_file, b"nested-bytes").unwrap();

    let mut request = base_request();
    request["file_access"] = json!([
        {"host_path": source, "guest_path": "/workspace/config.txt", "mode": "read_only"},
        {"host_path": nested_file, "guest_path": "/workspace/nested/data.bin", "mode": "read_write"}
    ]);
    request["egress"] = json!([
        {"host": "api.example.com", "method": "GET", "path": "/v1/status"},
        {"host": "uploads.example.com", "method": "POST", "path": "/v2/objects"}
    ]);

    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-abc123", &request);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("synthetic-test-value"));
    assert!(!stdout.contains(&source.display().to_string()));

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "agentsecret-supervisor/docker-plan/v1");
    assert_eq!(result["sandbox_name"], "agentsecret-run-abc123");
    assert_eq!(
        result["host_environment_to_remove"],
        json!(["SSH_AUTH_SOCK", "SSH_AGENT_PID"])
    );

    // Every command group is present as an argv array.
    for key in [
        "global_credential_audit",
        "sandbox_credential_audit",
        "account_policy_audit",
        "create",
        "sandbox_policy_audit",
        "verify_policy",
        "execute",
        "remove",
    ] {
        assert!(result[key].is_array(), "missing argv group {key}");
    }
    assert_eq!(result["allow_rules"].as_array().unwrap().len(), 2);

    let create = result["create"].as_array().unwrap();
    let create_text: Vec<&str> = create.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(create_text.contains(&"create"));
    assert!(create_text.contains(&"--skills"));
    assert!(create_text.contains(&"off"));
    assert!(create_text.contains(&"--static-mcp"));
    assert!(create_text.contains(&"none"));
    assert!(create_text.contains(&"shell"));
    // Two staged files produce two mount arguments ending in :ro / bare.
    let mounts: Vec<&&str> = create_text
        .iter()
        .filter(|arg| arg.contains(":/workspace/"))
        .collect();
    assert_eq!(mounts.len(), 2, "create argv: {create_text:?}");
    assert!(mounts.iter().any(|m| m.ends_with(":ro")));
    assert!(mounts.iter().any(|m| !m.ends_with(":ro")));
    let primary = scratch.join("primary");
    let caller_root = fs::canonicalize(&root).unwrap().display().to_string();
    assert!(!create_text.iter().any(|arg| *arg == caller_root));
    assert!(primary.join("nested").is_dir());
    assert_eq!(fs::read_dir(&primary).unwrap().count(), 1);

    let execute = result["execute"].as_array().unwrap();
    let execute_text: Vec<&str> = execute.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(execute_text[0], "--no-input");
    assert_eq!(execute_text[1], "exec");
    assert!(execute_text.contains(&"--workdir"));
    assert!(execute_text.contains(&"/workspace/project"));
    assert!(execute_text.contains(&"agentsecret-run-abc123"));
    assert!(execute_text.contains(&"/usr/bin/curl"));
    assert!(execute_text.contains(&"https://api.example.com/v1/status"));

    let remove = result["remove"].as_array().unwrap();
    let remove_text: Vec<&str> = remove.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(remove_text.contains(&"rm"));
    assert!(remove_text.contains(&"--force"));
    assert!(remove_text.contains(&"agentsecret-run-abc123"));

    // The allow rule argv carries the exact method/path per rule.
    let rules = result["allow_rules"].as_array().unwrap();
    let first: Vec<&str> = rules[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(first.contains(&"policy"));
    assert!(first.contains(&"allow"));
    assert!(first.contains(&"network"));
    assert!(first.contains(&"api.example.com:443"));
    assert!(first.contains(&"GET"));
    assert!(first.contains(&"/v1/status"));

    // Staged manifest matches the request and files exist with safe modes.
    let staged = result["staged_files"].as_array().unwrap();
    assert_eq!(staged.len(), 2);
    let scratch_canonical = fs::canonicalize(&scratch).unwrap();
    let staged_config = scratch_canonical.join("staged").join("config.txt");
    assert_eq!(fs::read(&staged_config).unwrap(), b"synthetic-test-value");
    assert_eq!(
        fs::metadata(&staged_config).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let staged_bin = scratch_canonical
        .join("staged")
        .join("nested")
        .join("data.bin");
    assert_eq!(
        fs::metadata(&staged_bin).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(scratch_canonical.join("guest").is_dir());
    assert_eq!(
        result["scratch"],
        json!(scratch_canonical.display().to_string())
    );
}

#[test]
fn docker_plan_cli_refuses_reference_bindings_before_staging() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let source = root.join("config.txt");
    fs::write(&source, b"synthetic").unwrap();
    let mut request = base_request();
    request["file_access"] = json!([
        {"host_path": source, "guest_path": "/workspace/config.txt", "mode": "read_only"}
    ]);
    request["reference_bindings"] = json!([
        {"env_name": "API_TOKEN", "alias": "example-api", "field_path": "/token"}
    ]);

    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-abc123", &request);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "sandbox_secret_binding_unsupported"
    );
    assert!(
        !scratch.exists(),
        "scratch must not be created for refused plans"
    );
}

#[test]
fn docker_plan_cli_rejects_invalid_request_without_creating_scratch() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let request = json!({
        "version": 1,
        "executable": "/usr/bin/curl",
        "argv": [],
        "working_directory": "/workspace",
        "secret": "synthetic-secret-sentinel"
    });
    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-abc123", &request);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "run_request_invalid_json"
    );
    assert!(!scratch.exists());
}

#[test]
fn docker_plan_cli_rejects_existing_scratch() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let scratch = temp.path().join("run-scratch");
    fs::create_dir(&scratch).unwrap();
    fs::write(scratch.join("keep.txt"), b"keep").unwrap();
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-abc123", &base_request());

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "run_scratch_create_failed"
    );
    assert_eq!(fs::read(scratch.join("keep.txt")).unwrap(), b"keep");
}

#[test]
fn docker_plan_cli_cleans_scratch_on_staging_failure() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let outside = temp.path().join("outside.txt");
    fs::write(&outside, b"synthetic").unwrap();
    let mut request = base_request();
    request["file_access"] = json!([
        {"host_path": outside, "guest_path": "/workspace/file.txt", "mode": "read_only"}
    ]);

    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-abc123", &request);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.trim(), "run_file_outside_workspace");
    assert!(!stderr.contains(&outside.display().to_string()));
    assert!(
        !scratch.exists(),
        "failed run must remove its scratch workspace"
    );
}

#[test]
fn docker_plan_cli_cleans_staged_scratch_when_output_pipe_is_closed() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let source = root.join("config.txt");
    fs::write(&source, b"synthetic").unwrap();
    let mut request = base_request();
    request["file_access"] = json!([
        {"host_path": source, "guest_path": "/workspace/config.txt", "mode": "read_only"}
    ]);

    let scratch = temp.path().join("run-scratch");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args(["docker-plan", "--host-root"])
        .arg(&root)
        .args(["--scratch"])
        .arg(&scratch)
        .args(["--sandbox-name", "agentsecret-run-closed-pipe"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start docker-plan supervisor");
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(request.to_string().as_bytes())
        .expect("write synthetic request");
    let output = child.wait_with_output().expect("wait for supervisor");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "run_result_write_failed"
    );
    assert!(
        !scratch.exists(),
        "staged files and scratch workspace must be removed after output failure"
    );
}

#[test]
fn docker_plan_cli_rejects_invalid_sandbox_name_and_cleans_scratch() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "INVALID_NAME!", &base_request());

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "sandbox_name_invalid"
    );
    assert!(!scratch.exists());
}

#[test]
fn docker_plan_cli_supports_empty_file_and_egress_declarations() {
    let temp = TestDir::new();
    let root = project_root(&temp);
    let scratch = temp.path().join("run-scratch");
    let output = run_docker_plan(&root, &scratch, "agentsecret-run-empty", &base_request());

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["allow_rules"].as_array().unwrap().len(), 0);
    assert_eq!(result["staged_files"].as_array().unwrap().len(), 0);
    let create = result["create"].as_array().unwrap();
    let mounts = create
        .iter()
        .filter(|arg| arg.as_str().is_some_and(|s| s.contains(":/workspace/")))
        .count();
    assert_eq!(mounts, 0);
}
