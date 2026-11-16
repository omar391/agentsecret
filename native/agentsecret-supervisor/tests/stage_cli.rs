use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("agentsecret-stage-cli-{}-{id}", std::process::id()));
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

fn run_stage(root: &Path, destination: &Path, request: &Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args(["stage", "--host-root"])
        .arg(root)
        .arg("--destination")
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start staging supervisor");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(request.to_string().as_bytes())
        .expect("write synthetic request");
    child
        .wait_with_output()
        .expect("wait for staging supervisor")
}

#[test]
fn stage_cli_copies_declared_file_and_emits_only_safe_metadata() {
    let temp = TestDir::new();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let source = root.join("config.txt");
    fs::write(&source, b"synthetic-test-value").unwrap();
    let destination = temp.path().join("staged");
    let request = json!({
        "version": 1,
        "executable": "/usr/bin/cat",
        "working_directory": "/workspace",
        "file_access": [{
            "host_path": source,
            "guest_path": "/workspace/config.txt",
            "mode": "read_only"
        }]
    });

    let output = run_stage(&root, &destination, &request);

    assert!(output.status.success());
    assert_eq!(
        fs::read(destination.join("config.txt")).unwrap(),
        b"synthetic-test-value"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-test-value"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&source.display().to_string()));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "agentsecret-supervisor/stage-result/v1");
    assert_eq!(result["files"][0]["guest_path"], "/workspace/config.txt");
    assert_eq!(result["files"][0]["mode"], "read_only");
    assert_eq!(result["files"][0]["byte_length"], 20);
}

#[test]
fn stage_cli_refuses_outside_sources_without_leaking_path_details() {
    let temp = TestDir::new();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let outside = temp.path().join("outside.txt");
    fs::write(&outside, b"synthetic").unwrap();
    let destination = temp.path().join("staged");
    let request = json!({
        "version": 1,
        "executable": "/usr/bin/cat",
        "working_directory": "/workspace",
        "file_access": [{
            "host_path": outside,
            "guest_path": "/workspace/file.txt",
            "mode": "read_only"
        }]
    });

    let output = run_stage(&root, &destination, &request);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "run_file_outside_workspace"
    );
    assert!(!destination.exists());
}

#[test]
fn stage_cli_rejects_secret_fields_and_oversized_stdin_without_echoing_input() {
    let temp = TestDir::new();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let destination = temp.path().join("staged");
    let request = json!({
        "version": 1,
        "executable": "/usr/bin/cat",
        "working_directory": "/workspace",
        "secret": "synthetic-secret-sentinel"
    });
    let output = run_stage(&root, &destination, &request);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "run_request_invalid_json"
    );
    assert!(!destination.exists());

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsecret-supervisor"))
        .args(["stage", "--host-root"])
        .arg(&root)
        .arg("--destination")
        .arg(&destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start staging supervisor");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&vec![b' '; 64 * 1024 + 1])
        .expect("write bounded oversized input");
    let output = child.wait_with_output().expect("wait for supervisor");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "run_request_too_large"
    );
    assert!(!destination.exists());
}
