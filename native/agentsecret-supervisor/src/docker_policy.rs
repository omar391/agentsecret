//! Compile validated run declarations to argument-safe Docker Sandboxes argv.
//!
//! This module only constructs argv. It does not execute `sbx`, inspect the
//! active local preset, or prove that organization policy permits the rules.
//! A caller must audit both account and sandbox policy before execution and
//! remove the sandbox after the run so its scoped rules are removed too.

use crate::{EgressRule, FileMode, StagedFile, ValidatedRunPlan};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Static failure codes for Docker policy compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerPolicyError {
    InvalidSandboxName,
    InvalidRule,
    InvalidWorkspace,
    InvalidStagedRoot,
    StagedFileMismatch,
    SecretBindingUnsupported,
}

impl std::fmt::Display for DockerPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSandboxName => "sandbox_name_invalid",
            Self::InvalidRule => "sandbox_egress_rule_invalid",
            Self::InvalidWorkspace => "sandbox_workspace_invalid",
            Self::InvalidStagedRoot => "sandbox_staged_root_invalid",
            Self::StagedFileMismatch => "sandbox_staged_file_mismatch",
            Self::SecretBindingUnsupported => "sandbox_secret_binding_unsupported",
        })
    }
}

impl std::error::Error for DockerPolicyError {}

/// Shell-free commands needed to provision, inspect, run, and remove one sandbox.
///
/// The account and sandbox policy queries are mandatory preflight steps. This
/// plan intentionally does not contain credential values or create a sandbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbxCommandPlan {
    /// Environment keys the host launcher must remove before spawning `sbx`.
    /// SSH-agent forwarding exposes a host signing capability to the guest.
    pub host_environment_to_remove: Vec<String>,
    /// Inspect global Docker Sandbox credential mappings without printing them.
    pub global_credential_audit: Vec<String>,
    /// Inspect mappings scoped to this generated sandbox name before creation.
    pub sandbox_credential_audit: Vec<String>,
    /// Inspect account/global rules before creating a sandbox.
    pub account_policy_audit: Vec<String>,
    /// Create a `shell` sandbox with a private primary workspace containing
    /// only declared-file parent directories and explicit file mounts.
    pub create: Vec<String>,
    /// Inspect inherited and sandbox-scoped rules before adding run grants.
    pub sandbox_policy_audit: Vec<String>,
    /// Exact per-sandbox HTTP grants. These do not prove the effective policy
    /// is deny-by-default; the caller must verify the postcondition.
    pub allow_rules: Vec<Vec<String>>,
    /// Read back the resulting policy after adding the exact grants.
    pub verify_policy: Vec<String>,
    /// Execute one explicit guest program and argv without a shell wrapper.
    pub execute: Vec<String>,
    /// Remove the sandbox and its scoped policy rules after completion.
    pub remove: Vec<String>,
}

/// Compile a run plan and its staged file manifest to direct `sbx` argv.
///
/// `primary_workspace` is an empty, supervisor-created private directory. It
/// contains only parent directories needed by declared file mounts, so the
/// caller's workspace is never exposed through the primary mount.
/// `guest_workspace` is retained as an independent empty-directory invariant;
/// it is not mounted. Staged files are mounted individually at their exact
/// declared guest paths so read-only files receive `:ro` mounts.
///
/// This compiler rejects secret reference bindings until a qualified adapter
/// can mediate them without exposing values in guest environment or argv.
/// Policy audit commands are returned but not run here.
pub fn compile_sbx_command_plan(
    plan: &ValidatedRunPlan,
    sandbox_name: &str,
    primary_workspace: &Path,
    guest_workspace: &Path,
    staged_root: &Path,
    staged_files: &[StagedFile],
) -> Result<SbxCommandPlan, DockerPolicyError> {
    if !valid_sandbox_name(sandbox_name)
        || !safe_host_path(primary_workspace)
        || !safe_host_path(guest_workspace)
        || !safe_host_path(staged_root)
        || primary_workspace == guest_workspace
        || primary_workspace == staged_root
        || guest_workspace == staged_root
        || !plan.reference_bindings.is_empty()
    {
        return Err(if !plan.reference_bindings.is_empty() {
            DockerPolicyError::SecretBindingUnsupported
        } else if !valid_sandbox_name(sandbox_name) {
            DockerPolicyError::InvalidSandboxName
        } else {
            DockerPolicyError::InvalidWorkspace
        });
    }
    if staged_files.len() != plan.file_access.len() {
        return Err(DockerPolicyError::StagedFileMismatch);
    }
    let primary_workspace = private_empty_directory(primary_workspace)?;
    private_empty_directory(guest_workspace)?;
    let staged_root = canonical_private_directory(staged_root, true)
        .map_err(|_| DockerPolicyError::InvalidStagedRoot)?;
    if paths_overlap(&primary_workspace, guest_workspace)
        || paths_overlap(&primary_workspace, &staged_root)
        || paths_overlap(guest_workspace, &staged_root)
    {
        return Err(DockerPolicyError::InvalidWorkspace);
    }

    let mut create = vec![
        "--no-input".to_owned(),
        "create".to_owned(),
        "--name".to_owned(),
        sandbox_name.to_owned(),
        "--skills".to_owned(),
        "off".to_owned(),
        "--static-mcp".to_owned(),
        "none".to_owned(),
        "shell".to_owned(),
        path_string(&primary_workspace)?,
        format!("{}:/workspace", path_string(&primary_workspace)?),
    ];
    for access in &plan.file_access {
        let file = staged_files
            .iter()
            .find(|file| file.guest_path == access.guest_path.as_str())
            .ok_or(DockerPolicyError::StagedFileMismatch)?;
        if file.mode != access.mode {
            return Err(DockerPolicyError::StagedFileMismatch);
        }
        let relative = access
            .guest_path
            .as_str()
            .strip_prefix("/workspace/")
            .ok_or(DockerPolicyError::StagedFileMismatch)?;
        if let Some(parent) = Path::new(relative).parent() {
            fs::create_dir_all(primary_workspace.join(parent))
                .map_err(|_| DockerPolicyError::InvalidWorkspace)?;
        }
        let source = staged_root.join(relative);
        validate_staged_file(&source, &staged_root, file)?;
        let source_text = path_string(&source)?;
        let target = access.guest_path.as_str();
        if target.contains(':') || target.contains('\n') || target.contains('\r') {
            return Err(DockerPolicyError::InvalidWorkspace);
        }
        let mount = match access.mode {
            FileMode::ReadOnly => format!("{source_text}:{target}:ro"),
            FileMode::ReadWrite => format!("{source_text}:{target}"),
        };
        create.push(mount);
    }

    let allow_rules = plan
        .egress
        .iter()
        .map(|rule| {
            let mut args = vec!["--no-input".to_owned()];
            args.extend(allow_rule_argv(sandbox_name, rule)?);
            Ok(args)
        })
        .collect::<Result<Vec<_>, DockerPolicyError>>()?;
    let mut execute = vec![
        "--no-input".to_owned(),
        "exec".to_owned(),
        "--workdir".to_owned(),
        plan.working_directory.as_str().to_owned(),
        sandbox_name.to_owned(),
        plan.executable.clone(),
    ];
    execute.extend(plan.argv.iter().cloned());

    Ok(SbxCommandPlan {
        host_environment_to_remove: vec!["SSH_AUTH_SOCK".into(), "SSH_AGENT_PID".into()],
        global_credential_audit: vec![
            "--no-input".into(),
            "secret".into(),
            "ls".into(),
            "--global".into(),
            "--format".into(),
            "json".into(),
        ],
        sandbox_credential_audit: vec![
            "--no-input".into(),
            "secret".into(),
            "ls".into(),
            "--sandbox".into(),
            sandbox_name.into(),
            "--format".into(),
            "json".into(),
        ],
        account_policy_audit: vec![
            "--no-input".into(),
            "policy".into(),
            "ls".into(),
            "--wide".into(),
            "--include-inactive".into(),
            "--format".into(),
            "json".into(),
        ],
        create,
        sandbox_policy_audit: vec![
            "--no-input".into(),
            "policy".into(),
            "ls".into(),
            sandbox_name.into(),
            "--wide".into(),
            "--include-inactive".into(),
            "--format".into(),
            "json".into(),
        ],
        allow_rules,
        verify_policy: vec![
            "--no-input".into(),
            "policy".into(),
            "ls".into(),
            sandbox_name.into(),
            "--wide".into(),
            "--include-inactive".into(),
            "--format".into(),
            "json".into(),
        ],
        execute,
        remove: vec![
            "--no-input".into(),
            "rm".into(),
            "--force".into(),
            sandbox_name.into(),
        ],
    })
}

fn safe_host_path(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some_and(|value| {
            !value.contains(':')
                && !value.contains('\0')
                && !value.contains('\n')
                && !value.contains('\r')
        })
}

fn path_string(path: &Path) -> Result<String, DockerPolicyError> {
    if !safe_host_path(path) {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    let canonical = fs::canonicalize(path).map_err(|_| DockerPolicyError::InvalidWorkspace)?;
    if canonical != path {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    canonical
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(DockerPolicyError::InvalidWorkspace)
}

fn private_empty_directory(path: &Path) -> Result<PathBuf, DockerPolicyError> {
    let canonical =
        canonical_private_directory(path, true).map_err(|_| DockerPolicyError::InvalidWorkspace)?;
    if fs::read_dir(&canonical)
        .map_err(|_| DockerPolicyError::InvalidWorkspace)?
        .next()
        .is_some()
    {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    Ok(canonical)
}

fn canonical_private_directory(
    path: &Path,
    require_private_mode: bool,
) -> Result<PathBuf, DockerPolicyError> {
    if !safe_host_path(path) {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| DockerPolicyError::InvalidWorkspace)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (require_private_mode && metadata.permissions().mode() & 0o077 != 0)
    {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    let canonical = fs::canonicalize(path).map_err(|_| DockerPolicyError::InvalidWorkspace)?;
    if canonical != path {
        return Err(DockerPolicyError::InvalidWorkspace);
    }
    Ok(canonical)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_staged_file(
    source: &Path,
    staged_root: &Path,
    declaration: &StagedFile,
) -> Result<(), DockerPolicyError> {
    let metadata =
        fs::symlink_metadata(source).map_err(|_| DockerPolicyError::InvalidStagedRoot)?;
    let expected_mode = match declaration.mode {
        FileMode::ReadOnly => 0o400,
        FileMode::ReadWrite => 0o600,
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() != declaration.byte_length
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(DockerPolicyError::StagedFileMismatch);
    }
    let canonical = fs::canonicalize(source).map_err(|_| DockerPolicyError::InvalidStagedRoot)?;
    if canonical != source || !canonical.starts_with(staged_root) {
        return Err(DockerPolicyError::InvalidStagedRoot);
    }
    Ok(())
}

/// Return one `sbx policy allow network` argv for an exact HTTP rule.
///
/// Args are separate tokens for `Command::args`; callers must not join them
/// into a shell command. The sandbox name is restricted to a safe generated
/// identifier. Paths with wildcards or noncanonical separators fail closed.
pub fn allow_rule_argv(
    sandbox_name: &str,
    rule: &EgressRule,
) -> Result<Vec<String>, DockerPolicyError> {
    if !valid_sandbox_name(sandbox_name) {
        return Err(DockerPolicyError::InvalidSandboxName);
    }
    if !crate::is_supported_http_method(&rule.method)
        || !crate::is_dns_hostname(&rule.host)
        || !crate::is_exact_path(&rule.path)
    {
        return Err(DockerPolicyError::InvalidRule);
    }
    Ok(vec![
        "policy".into(),
        "allow".into(),
        "network".into(),
        "--sandbox".into(),
        sandbox_name.into(),
        format!("{}:443", rule.host),
        "--method".into(),
        rule.method.clone(),
        "--path".into(),
        rule.path.clone(),
    ])
}

fn valid_sandbox_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileMode, parse_run_request};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("agentsecret-sbx-plan-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create test directory");
            let path = fs::canonicalize(path).expect("canonical test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure test directory");
            Self(path)
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).expect("create workspace directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure workspace directory");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn stage_file(root: &Path, relative: &str, contents: &[u8], mode: FileMode) -> StagedFile {
        let source = root.join(relative);
        fs::create_dir_all(source.parent().expect("file parent")).expect("create staged parent");
        fs::write(&source, contents).expect("write staged fixture");
        fs::set_permissions(
            &source,
            fs::Permissions::from_mode(match mode {
                FileMode::ReadOnly => 0o400,
                FileMode::ReadWrite => 0o600,
            }),
        )
        .expect("set staged file mode");
        StagedFile {
            guest_path: format!("/workspace/{relative}"),
            mode,
            byte_length: contents.len() as u64,
        }
    }

    fn valid_plan() -> ValidatedRunPlan {
        let input = br#"{
          "version": 1,
          "executable": "/usr/bin/curl",
          "argv": ["--silent", "--show-error", "a;$(not-a-shell)"],
          "working_directory": "/workspace/project",
          "file_access": [{
            "host_path": "/Users/test/project/config.json",
            "guest_path": "/workspace/project/config.json",
            "mode": "read_only"
          }],
          "egress": [{
            "host": "api.example.com",
            "method": "GET",
            "path": "/v1/status"
          }]
        }"#;
        parse_run_request(input).expect("valid request")
    }

    fn rule() -> EgressRule {
        EgressRule {
            host: "api.example.com".into(),
            method: "GET".into(),
            path: "/v1/status".into(),
        }
    }

    #[test]
    fn emits_scoped_exact_http_policy_as_argv_tokens() {
        assert_eq!(
            allow_rule_argv("agentsecret-a1b2c3", &rule()).unwrap(),
            [
                "policy",
                "allow",
                "network",
                "--sandbox",
                "agentsecret-a1b2c3",
                "api.example.com:443",
                "--method",
                "GET",
                "--path",
                "/v1/status"
            ]
        );
    }

    #[test]
    fn rejects_shell_fragments_and_wildcard_or_non_http_rules() {
        assert_eq!(
            allow_rule_argv("safe;touch", &rule()),
            Err(DockerPolicyError::InvalidSandboxName)
        );
        let mut wildcard = rule();
        wildcard.path = "/v1/**".into();
        assert_eq!(
            allow_rule_argv("agentsecret-run1", &wildcard),
            Err(DockerPolicyError::InvalidRule)
        );
        let mut unusual = rule();
        unusual.method = "CUSTOM".into();
        assert_eq!(
            allow_rule_argv("agentsecret-run1", &unusual),
            Err(DockerPolicyError::InvalidRule)
        );
        for method in ["CONNECT", "TRACE"] {
            let mut tunnel = rule();
            tunnel.method = method.to_owned();
            assert_eq!(
                allow_rule_argv("agentsecret-run1", &tunnel),
                Err(DockerPolicyError::InvalidRule)
            );
        }
    }

    #[test]
    fn compiles_explicit_workspace_mounts_and_literal_exec_argv() {
        let plan = valid_plan();
        let temp = TestDir::new();
        let primary = temp.directory("primary");
        let guest_workspace = temp.directory("guest-workspace");
        let staged_root = temp.directory("staged");
        let staged = [stage_file(
            &staged_root,
            "project/config.json",
            b"synthetic-config",
            FileMode::ReadOnly,
        )];
        let commands = compile_sbx_command_plan(
            &plan,
            "agentsecret-run1",
            &primary,
            &guest_workspace,
            &staged_root,
            &staged,
        )
        .expect("command plan");

        assert_eq!(
            &commands.create[..11],
            [
                "--no-input",
                "create",
                "--name",
                "agentsecret-run1",
                "--skills",
                "off",
                "--static-mcp",
                "none",
                "shell",
                primary.to_str().expect("utf8 test path"),
                format!("{}:/workspace", primary.display()).as_str(),
            ]
        );
        assert_eq!(commands.create.len(), 12);
        assert_eq!(
            commands.create[11],
            format!(
                "{}:/workspace/project/config.json:ro",
                staged_root.join("project/config.json").display()
            )
        );
        assert_eq!(
            commands.host_environment_to_remove,
            ["SSH_AUTH_SOCK", "SSH_AGENT_PID"]
        );
        assert_eq!(
            commands.global_credential_audit,
            ["--no-input", "secret", "ls", "--global", "--format", "json"]
        );
        assert_eq!(
            commands.sandbox_credential_audit,
            [
                "--no-input",
                "secret",
                "ls",
                "--sandbox",
                "agentsecret-run1",
                "--format",
                "json"
            ]
        );
        assert_eq!(
            commands.execute,
            [
                "--no-input",
                "exec",
                "--workdir",
                "/workspace/project",
                "agentsecret-run1",
                "/usr/bin/curl",
                "--silent",
                "--show-error",
                "a;$(not-a-shell)"
            ]
        );
        assert_eq!(
            commands.account_policy_audit,
            [
                "--no-input",
                "policy",
                "ls",
                "--wide",
                "--include-inactive",
                "--format",
                "json"
            ]
        );
        assert_eq!(commands.allow_rules.len(), 1);
        assert_eq!(
            commands.remove,
            ["--no-input", "rm", "--force", "agentsecret-run1"]
        );
    }

    #[test]
    fn command_plan_refuses_secret_bindings_and_manifest_mismatch() {
        let mut plan = valid_plan();
        plan.reference_bindings.push(crate::ReferenceBinding {
            env_name: "API_TOKEN".into(),
            alias: "synthetic-alias".into(),
            field_path: None,
        });
        let files = [StagedFile {
            guest_path: "/workspace/project/config.json".into(),
            mode: FileMode::ReadOnly,
            byte_length: 16,
        }];
        assert_eq!(
            compile_sbx_command_plan(
                &plan,
                "agentsecret-run1",
                Path::new("/tmp/agentsecret-run1/primary"),
                Path::new("/tmp/agentsecret-run1/empty-workspace"),
                Path::new("/tmp/agentsecret-run1/staged"),
                &files,
            ),
            Err(DockerPolicyError::SecretBindingUnsupported)
        );

        let plan = valid_plan();
        assert_eq!(
            compile_sbx_command_plan(
                &plan,
                "agentsecret-run1",
                Path::new("/tmp/agentsecret-run1/primary"),
                Path::new("/tmp/agentsecret-run1/empty-workspace"),
                Path::new("/tmp/agentsecret-run1/staged"),
                &[],
            ),
            Err(DockerPolicyError::StagedFileMismatch)
        );
    }

    #[test]
    fn command_plan_preserves_each_declared_file_mode() {
        let input = br#"{
          "version": 1,
          "executable": "/usr/bin/tool",
          "argv": [],
          "working_directory": "/workspace/project",
          "file_access": [
            {"host_path":"/Users/test/project/read.txt","guest_path":"/workspace/project/read.txt","mode":"read_only"},
            {"host_path":"/Users/test/project/write.txt","guest_path":"/workspace/project/write.txt","mode":"read_write"}
          ]
        }"#;
        let plan = parse_run_request(input).expect("valid request");
        let temp = TestDir::new();
        let primary = temp.directory("primary");
        let guest_workspace = temp.directory("guest-workspace");
        let staged_root = temp.directory("staged");
        let staged = [
            stage_file(
                &staged_root,
                "project/read.txt",
                b"read",
                FileMode::ReadOnly,
            ),
            stage_file(
                &staged_root,
                "project/write.txt",
                b"write",
                FileMode::ReadWrite,
            ),
        ];
        let commands = compile_sbx_command_plan(
            &plan,
            "agentsecret-run2",
            &primary,
            &guest_workspace,
            &staged_root,
            &staged,
        )
        .expect("command plan");

        assert!(commands.create.iter().any(|argument| {
            argument
                == &format!(
                    "{}:/workspace/project/read.txt:ro",
                    staged_root.join("project/read.txt").display()
                )
        }));
        assert!(commands.create.iter().any(|argument| {
            argument
                == &format!(
                    "{}:/workspace/project/write.txt",
                    staged_root.join("project/write.txt").display()
                )
        }));
    }

    #[test]
    fn command_plan_refuses_nonempty_scratch_and_changed_staged_modes() {
        let plan = valid_plan();
        let temp = TestDir::new();
        let primary = temp.directory("primary");
        let guest_workspace = temp.directory("guest-workspace");
        let staged_root = temp.directory("staged");
        let staged = [stage_file(
            &staged_root,
            "project/config.json",
            b"synthetic-config",
            FileMode::ReadOnly,
        )];
        fs::write(guest_workspace.join("unexpected.txt"), b"unexpected")
            .expect("write unexpected scratch entry");

        assert_eq!(
            compile_sbx_command_plan(
                &plan,
                "agentsecret-run3",
                &primary,
                &guest_workspace,
                &staged_root,
                &staged,
            ),
            Err(DockerPolicyError::InvalidWorkspace)
        );

        fs::remove_file(guest_workspace.join("unexpected.txt")).expect("remove scratch fixture");
        fs::set_permissions(
            staged_root.join("project/config.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("change staged mode");
        assert_eq!(
            compile_sbx_command_plan(
                &plan,
                "agentsecret-run3",
                &primary,
                &guest_workspace,
                &staged_root,
                &staged,
            ),
            Err(DockerPolicyError::StagedFileMismatch)
        );
    }
}
