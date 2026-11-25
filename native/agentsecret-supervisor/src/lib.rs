//! Parse and validate the JSON contract accepted by the native run supervisor.
//!
//! This crate does not launch a workload. A validated plan is still untrusted
//! input and must be authorized against the current account policy before a
//! qualified backend may stage files, bind references, or start a guest.

use serde::Deserialize;
use std::fmt::{Display, Formatter};

pub mod staging;
pub use staging::{
    StagedFile, StagingError, stage_declared_files, stage_declared_files_with_limits,
};
pub mod docker_policy;
pub use docker_policy::{DockerPolicyError, allow_rule_argv};
pub mod gateway;
pub mod git_wire;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 128;
const MAX_FILE_ACCESS: usize = 64;
const MAX_BINDINGS: usize = 32;
const MAX_EGRESS_RULES: usize = 64;
const WORKSPACE_ROOT: &str = "/workspace";

/// One opaque guest environment token read from a host-private binding file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunBinding {
    pub env_name: String,
    pub alias: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunBinding {
    env_name: String,
    alias: String,
    token: String,
}

/// Read and validate the host-private token map for a mediated run.
///
/// # Errors
/// Returns [RunSpecError::InvalidRequest] for unsafe paths or malformed files.
pub fn read_binding_file(path: &str) -> Result<Vec<RunBinding>, RunSpecError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !is_host_absolute_path(path) {
        return Err(RunSpecError::InvalidRequest);
    }
    let file = std::fs::File::open(path).map_err(|_| RunSpecError::InvalidRequest)?;
    let metadata = file.metadata().map_err(|_| RunSpecError::InvalidRequest)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(RunSpecError::InvalidRequest);
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunSpecError::InvalidRequest)?;
    if bytes.len() > 64 * 1024 {
        return Err(RunSpecError::InvalidRequest);
    }
    let raw: Vec<RawRunBinding> =
        serde_json::from_slice(&bytes).map_err(|_| RunSpecError::InvalidRequest)?;
    raw.into_iter()
        .map(|binding| {
            if !is_env_name(&binding.env_name)
                || !is_alias(&binding.alias)
                || !is_placeholder(Some(&binding.token), &binding.alias)
            {
                return Err(RunSpecError::InvalidRequest);
            }
            Ok(RunBinding {
                env_name: binding.env_name,
                alias: binding.alias,
                token: binding.token,
            })
        })
        .collect()
}

/// Require the private token map to match every declared binding exactly.
pub fn binding_map_matches(declared: &[ReferenceBinding], bindings: &[RunBinding]) -> bool {
    declared.len() == bindings.len()
        && declared.iter().zip(bindings).all(|(declared, binding)| {
            declared.env_name.eq_ignore_ascii_case(&binding.env_name)
                && declared.alias == binding.alias
                && declared.placeholder.as_deref() == Some(binding.token.as_str())
        })
}

/// One opaque guest environment entry read from the private dotenv file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvBinding {
    pub env_name: String,
    pub token: String,
}

/// Read and validate the host-private dotenv file consumed by sbx exec.
///
/// # Errors
/// Returns [RunSpecError::InvalidRequest] for unsafe paths or malformed lines.
pub fn read_env_file(path: &str) -> Result<Vec<EnvBinding>, RunSpecError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !is_host_absolute_path(path) {
        return Err(RunSpecError::InvalidRequest);
    }
    let file = std::fs::File::open(path).map_err(|_| RunSpecError::InvalidRequest)?;
    let metadata = file.metadata().map_err(|_| RunSpecError::InvalidRequest)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(RunSpecError::InvalidRequest);
    }
    let mut text = String::new();
    file.take(64 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| RunSpecError::InvalidRequest)?;
    if text.len() > 64 * 1024 {
        return Err(RunSpecError::InvalidRequest);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(RunSpecError::InvalidRequest)?;
        if !is_env_name(name) || value.is_empty() {
            return Err(RunSpecError::InvalidRequest);
        }
        out.push(EnvBinding {
            env_name: name.to_owned(),
            token: value.to_owned(),
        });
    }
    Ok(out)
}

/// Require the private dotenv map to match every declared binding exactly.
pub fn env_map_matches(declared: &[ReferenceBinding], env: &[EnvBinding]) -> bool {
    declared.len() == env.len()
        && declared.iter().zip(env.iter()).all(|(declared, env)| {
            declared.env_name == env.env_name
                && declared.placeholder.as_deref() == Some(env.token.as_str())
        })
}

/// Methods supported by the cloud broker and the managed-runtime egress contract.
/// CONNECT and TRACE are intentionally excluded because they can expose tunnel
/// or tracing behavior outside the exact HTTP request model.
pub fn is_supported_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

/// A static failure code. It deliberately contains no request data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSpecError {
    /// The input exceeded the fixed request size limit.
    InputTooLarge,
    /// The input was not valid JSON or did not match the closed schema.
    InvalidJson,
    /// A value did not satisfy the request contract.
    InvalidRequest,
}

impl Display for RunSpecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "run_request_too_large",
            Self::InvalidJson => "run_request_invalid_json",
            Self::InvalidRequest => "run_request_invalid",
        })
    }
}

impl std::error::Error for RunSpecError {}

/// A normalized absolute POSIX path inside the guest workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestPath(String);

impl GuestPath {
    /// Returns the path without allocating.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A process invocation with explicit file, credential-reference and egress
/// declarations. It contains no credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRunPlan {
    /// Protocol version understood by this supervisor.
    pub version: u8,
    /// Explicit Linux guest executable path.
    pub executable: String,
    /// Literal argv entries passed directly to the executable, never through a shell.
    pub argv: Vec<String>,
    /// Guest working directory constrained to `/workspace`.
    pub working_directory: GuestPath,
    /// Explicit host-to-guest file declarations for the backend to authorize and stage.
    pub file_access: Vec<FileAccess>,
    /// Opaque credential references; no secret material is accepted in this contract.
    pub reference_bindings: Vec<ReferenceBinding>,
    /// Host-side mediation endpoint and private alias-token map for this run.
    pub mediation: Option<RunMediation>,
    /// Exact HTTPS destinations the trusted supervisor may mediate.
    pub egress: Vec<EgressRule>,
}

/// A declared host file transfer. Authorization and race-safe staging remain
/// mandatory backend responsibilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAccess {
    /// Host-side source path, validated syntactically but not opened here.
    pub host_path: String,
    /// Absolute guest-side destination under `/workspace`.
    pub guest_path: GuestPath,
    /// Requested access mode.
    pub mode: FileMode,
}

/// Requested filesystem access mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileMode {
    /// The guest may read the staged data.
    ReadOnly,
    /// The guest may read and update its isolated copy.
    ReadWrite,
}

/// A binding from a guest environment variable to a policy-owned alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBinding {
    /// Guest environment variable name.
    pub env_name: String,
    /// AgentSecret alias selected by the caller.
    pub alias: String,
    /// Optional exact provider field reference, never a value.
    pub field_path: Option<String>,
    /// Opaque per-run placeholder token. The host replaces this with the
    /// exact alias policy binding only inside the guest environment.
    pub placeholder: Option<String>,
}

/// The host-only mediation contract for a run with reference bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunMediation {
    /// Loopback origin of the host mediator, for example http://127.0.0.1:1/.
    pub mediator_origin: String,
    /// Host-private JSON file mapping environment names to opaque tokens.
    pub binding_file: String,
    /// Host-private dotenv file consumed only by sbx exec --env-file.
    pub env_file: String,
}

/// A destination-specific HTTPS rule for the supervisor's outbound adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressRule {
    /// Lowercase DNS hostname without a port or wildcard.
    pub host: String,
    /// Exact uppercase HTTP method.
    pub method: String,
    /// Exact path without query, fragment or wildcard.
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunRequest {
    version: u8,
    executable: String,
    #[serde(default)]
    argv: Vec<String>,
    working_directory: String,
    #[serde(default)]
    file_access: Vec<RawFileAccess>,
    #[serde(default)]
    reference_bindings: Vec<RawReferenceBinding>,
    #[serde(default)]
    mediation: Option<RawMediation>,
    #[serde(default)]
    egress: Vec<RawEgressRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileAccess {
    host_path: String,
    guest_path: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReferenceBinding {
    env_name: String,
    alias: String,
    #[serde(default)]
    field_path: Option<String>,
    #[serde(default)]
    placeholder: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMediation {
    mediator_origin: String,
    binding_file: String,
    env_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgressRule {
    host: String,
    method: String,
    path: String,
    #[serde(default = "https_port")]
    port: u16,
}

fn https_port() -> u16 {
    443
}

/// Parse an untrusted JSON request into a validated, secret-free run plan.
///
/// This establishes only structural validity. It does not authorize the
/// caller, canonicalize or open host paths, or prove that an egress backend
/// cannot be bypassed.
///
/// # Errors
/// Returns a stable, data-free error code for malformed or unsafe requests.
pub fn parse_run_request(input: &[u8]) -> Result<ValidatedRunPlan, RunSpecError> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(RunSpecError::InputTooLarge);
    }
    let raw: RawRunRequest =
        serde_json::from_slice(input).map_err(|_| RunSpecError::InvalidJson)?;
    validate(raw)
}

fn validate(raw: RawRunRequest) -> Result<ValidatedRunPlan, RunSpecError> {
    if raw.version != 1
        || !is_guest_absolute_path(&raw.executable)
        || !is_workspace_path(&raw.working_directory)
        || raw.argv.len() > MAX_ARGUMENTS
        || raw.argv.iter().any(|arg| arg.contains('\0'))
        || raw.file_access.len() > MAX_FILE_ACCESS
        || raw.reference_bindings.len() > MAX_BINDINGS
        || raw.egress.len() > MAX_EGRESS_RULES
    {
        return Err(RunSpecError::InvalidRequest);
    }

    let mut targets = std::collections::HashSet::with_capacity(raw.file_access.len());
    let mut file_access = Vec::with_capacity(raw.file_access.len());
    for access in raw.file_access {
        if !is_host_absolute_path(&access.host_path) || !is_workspace_path(&access.guest_path) {
            return Err(RunSpecError::InvalidRequest);
        }
        let mode = match access.mode.as_str() {
            "read_only" => FileMode::ReadOnly,
            "read_write" => FileMode::ReadWrite,
            _ => return Err(RunSpecError::InvalidRequest),
        };
        if !targets.insert(access.guest_path.clone()) {
            return Err(RunSpecError::InvalidRequest);
        }
        file_access.push(FileAccess {
            host_path: access.host_path,
            guest_path: GuestPath(access.guest_path),
            mode,
        });
    }

    let mut env_names = std::collections::HashSet::with_capacity(raw.reference_bindings.len());
    let mut reference_bindings = Vec::with_capacity(raw.reference_bindings.len());
    let mediation = raw
        .mediation
        .map(|value| {
            let binding_file = value.binding_file;
            let env_file = value.env_file;
            if !is_host_absolute_path(&binding_file)
                || !is_host_absolute_path(&env_file)
                || !is_local_mediator_origin(&value.mediator_origin)
            {
                return Err(RunSpecError::InvalidRequest);
            }
            Ok(RunMediation {
                mediator_origin: value.mediator_origin,
                binding_file,
                env_file,
            })
        })
        .transpose()?;
    for binding in raw.reference_bindings {
        if !is_env_name(&binding.env_name)
            || !is_alias(&binding.alias)
            || !env_names.insert(binding.env_name.to_ascii_lowercase())
            || binding
                .field_path
                .as_deref()
                .is_some_and(|path| !is_field_path(path))
            || !is_placeholder(binding.placeholder.as_deref(), &binding.alias)
        {
            return Err(RunSpecError::InvalidRequest);
        }
        reference_bindings.push(ReferenceBinding {
            env_name: binding.env_name,
            alias: binding.alias,
            field_path: binding.field_path,
            placeholder: binding.placeholder,
        });
    }
    if reference_bindings.is_empty() && mediation.is_some() {
        return Err(RunSpecError::InvalidRequest);
    }
    if !reference_bindings.is_empty() && mediation.is_none() {
        return Err(RunSpecError::InvalidRequest);
    }

    let mut egress_keys = std::collections::HashSet::with_capacity(raw.egress.len());
    let mut egress = Vec::with_capacity(raw.egress.len());
    for rule in raw.egress {
        if rule.port != 443
            || !is_dns_hostname(&rule.host)
            || !is_supported_http_method(&rule.method)
            || !is_exact_path(&rule.path)
        {
            return Err(RunSpecError::InvalidRequest);
        }
        let key = format!("{}\0{}\0{}", rule.host, rule.method, rule.path);
        if !egress_keys.insert(key) {
            return Err(RunSpecError::InvalidRequest);
        }
        egress.push(EgressRule {
            host: rule.host,
            method: rule.method,
            path: rule.path,
        });
    }

    Ok(ValidatedRunPlan {
        version: raw.version,
        executable: raw.executable,
        argv: raw.argv,
        working_directory: GuestPath(raw.working_directory),
        file_access,
        reference_bindings,
        mediation,
        egress,
    })
}

/// Whether this is a loopback-only HTTP mediator origin.
pub fn is_local_mediator_origin(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    if rest.contains('@') || rest.contains('/') || rest.contains('\\') {
        return false;
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rest, ""),
    };
    if !path.is_empty() {
        return false;
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        return matches!(host, "127.0.0.1" | "[::1]")
            && port.len() <= 5
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && !port.is_empty();
    }
    matches!(authority, "127.0.0.1" | "[::1]")
}

fn is_guest_absolute_path(value: &str) -> bool {
    value.starts_with('/') && safe_posix_components(value) && value != "/"
}

fn is_workspace_path(value: &str) -> bool {
    is_guest_absolute_path(value) && (value == WORKSPACE_ROOT || value.starts_with("/workspace/"))
}

fn safe_posix_components(value: &str) -> bool {
    value.starts_with('/')
        && !value.contains('\0')
        && !value.contains('\\')
        && (value == "/"
            || (!value.ends_with('/')
                && value[1..]
                    .split('/')
                    .all(|component| !component.is_empty() && !matches!(component, "." | ".."))))
}

fn is_host_absolute_path(value: &str) -> bool {
    safe_posix_components(value)
        && !value.contains('\0')
        && !value.contains('\n')
        && !value.contains('\r')
}

fn is_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    value != "PATH"
        && !value.starts_with("AGENTSECRET_")
        && matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
        && value.len() <= 128
}

fn is_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_field_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 512
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

fn is_placeholder(value: Option<&str>, alias: &str) -> bool {
    let Some(value) = value else { return true };
    let prefix = format!("ASRC1.{alias}.");
    value.starts_with(&prefix)
        && value.len() == prefix.len() + 43
        && value
            .bytes()
            .skip(prefix.len())
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn is_dns_hostname(value: &str) -> bool {
    if value.len() < 4 || value.len() > 253 || value != value.to_ascii_lowercase() {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let mut labels = value.split('.');
    let mut count = 0usize;
    for label in &mut labels {
        count += 1;
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return false;
        }
    }
    count >= 2 && !value.ends_with(".local") && !value.ends_with(".localhost")
}

fn is_exact_path(value: &str) -> bool {
    safe_posix_components(value)
        && !value.contains('*')
        && !value.contains('?')
        && !value.contains('#')
        // Docker's local HTTP policy requires canonical paths without
        // percent-encoding or whitespace, otherwise the proxy's normalized
        // request path could differ from the manifest's exact path.
        && !value.contains('%')
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
        && !value.contains('\n')
        && !value.contains('\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> &'static [u8] {
        br#"{
          "version": 1,
          "executable": "/usr/bin/curl",
          "argv": ["--silent", "--show-error", "https://api.example.com/v1/status"],
          "working_directory": "/workspace/project",
          "file_access": [{
            "host_path": "/Users/test/project/config.json",
            "guest_path": "/workspace/project/config.json",
            "mode": "read_only"
          }],
          "reference_bindings": [{
            "env_name": "API_TOKEN",
          "alias": "EXAMPLE_API",
          "field_path": "/token",
          "placeholder": "ASRC1.EXAMPLE_API.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          }],
        "mediation": {
          "mediator_origin": "http://127.0.0.1:49151",
          "binding_file": "/tmp/agentsecret-bindings.json",
          "env_file": "/tmp/agentsecret-guest.env"
        },
          "egress": [{
            "host": "api.example.com",
            "method": "GET",
            "path": "/v1/status"
          }]
        }"#
    }

    #[test]
    fn parses_literal_argv_and_typed_capability_references() {
        let plan = parse_run_request(valid_request()).expect("valid request");
        assert_eq!(plan.executable, "/usr/bin/curl");
        assert_eq!(plan.argv[0], "--silent");
        assert_eq!(plan.working_directory.as_str(), "/workspace/project");
        assert_eq!(plan.file_access[0].mode, FileMode::ReadOnly);
        assert_eq!(plan.reference_bindings[0].alias, "EXAMPLE_API");
        assert_eq!(plan.egress[0].host, "api.example.com");
    }

    #[test]
    fn request_cannot_smuggle_secret_values_or_unknown_fields() {
        let input = br#"{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","secret":"synthetic-value"}"#;
        assert_eq!(parse_run_request(input), Err(RunSpecError::InvalidJson));
    }

    #[test]
    fn rejects_host_path_traversal_and_guest_escape() {
        for path in [
            "/workspace/../etc/passwd",
            "/workspace//../../secret",
            "/workspace//project",
            "/Users/test/project",
        ] {
            let input = format!(
                r#"{{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"{path}"}}"#
            );
            assert_eq!(
                parse_run_request(input.as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        for host_path in ["relative/file", "/tmp/../secret", "/tmp//secret"] {
            let input = format!(
                r#"{{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","file_access":[{{"host_path":"{host_path}","guest_path":"/workspace/file","mode":"read_only"}}]}}"#
            );
            assert_eq!(
                parse_run_request(input.as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
    }

    #[test]
    fn rejects_shell_control_bytes_and_duplicate_environment_bindings() {
        let input = br#"{"version":1,"executable":"/usr/bin/curl","argv":["x\u0000y"],"working_directory":"/workspace"}"#;
        assert_eq!(parse_run_request(input), Err(RunSpecError::InvalidRequest));

        let input = br#"{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","reference_bindings":[{"env_name":"API_TOKEN","alias":"ONE"},{"env_name":"api_token","alias":"TWO"}]}"#;
        assert_eq!(parse_run_request(input), Err(RunSpecError::InvalidRequest));
    }

    #[test]
    fn reference_bindings_match_the_broker_and_cli_boundaries() {
        let valid = serde_json::json!({
            "version": 1, "executable": "/usr/bin/true", "argv": [],
            "working_directory": "/workspace",
            "reference_bindings": [{
                "env_name": "API_TOKEN",
                "alias": "VALID_ALIAS",
                "field_path": "/x",
                "placeholder": "ASRC1.VALID_ALIAS.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }],
            "mediation": {
                "mediator_origin": "http://127.0.0.1:49151",
                "binding_file": "/tmp/agentsecret-bindings.json",
                "env_file": "/tmp/agentsecret-guest.env"
            }
        });
        let make = |name: &str, alias: &str, path: &str| {
            let mut value = valid.clone();
            value["reference_bindings"][0]["env_name"] = serde_json::json!(name);
            value["reference_bindings"][0]["alias"] = serde_json::json!(alias);
            value["reference_bindings"][0]["field_path"] = serde_json::json!(path);
            value.to_string()
        };
        for alias in ["A-B", "A.B", "1A", "lowercase", &"A".repeat(65)] {
            assert_eq!(
                parse_run_request(make("API_TOKEN", alias, "/login/password").as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        for name in ["PATH", "AGENTSECRET_TOKEN"] {
            assert_eq!(
                parse_run_request(make(name, "VALID_ALIAS", "/login/password").as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        for path in ["/x\ty", "/x\u{7}y", "/x\u{7f}y"] {
            assert_eq!(
                parse_run_request(make("API_TOKEN", "VALID_ALIAS", path).as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        let mut longest = valid.clone();
        longest["reference_bindings"][0]["alias"] = serde_json::json!("A".repeat(64));
        longest["reference_bindings"][0]["placeholder"] =
            serde_json::json!(format!("ASRC1.{}.", "A".repeat(64)) + &"B".repeat(43));
        assert!(parse_run_request(longest.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn egress_requires_exact_https_dns_destination() {
        for host in [
            "*.example.com",
            "127.0.0.1",
            "api.local",
            "UPPER.example.com",
        ] {
            let input = format!(
                r#"{{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","egress":[{{"host":"{host}","method":"GET","path":"/v1"}}]}}"#
            );
            assert_eq!(
                parse_run_request(input.as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        for method in ["CONNECT", "TRACE", "PROPFIND", "get"] {
            let input = format!(
                r#"{{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","egress":[{{"host":"api.example.com","method":"{method}","path":"/v1"}}]}}"#
            );
            assert_eq!(
                parse_run_request(input.as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        for path in [
            "/v1/*",
            "/v1//status",
            "/v1/../status",
            "/v1/%2e%2e/status",
            "/v1/status ",
            "/v1/status/",
        ] {
            let input = format!(
                r#"{{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","egress":[{{"host":"api.example.com","method":"GET","path":"{path}"}}]}}"#
            );
            assert_eq!(
                parse_run_request(input.as_bytes()),
                Err(RunSpecError::InvalidRequest)
            );
        }
        let input = br#"{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","egress":[{"host":"api.example.com","method":"GET","path":"/v1/status\t"}]}"#;
        assert_eq!(parse_run_request(input), Err(RunSpecError::InvalidRequest));
    }

    #[test]
    fn run_egress_methods_match_the_broker_allowlist() {
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            assert!(
                is_supported_http_method(method),
                "{method} must be supported"
            );
        }
        for method in [
            "CONNECT", "TRACE", "PROPFIND", "PRI", "PURGE", "get", "CUSTOM",
        ] {
            assert!(
                !is_supported_http_method(method),
                "{method} must be refused"
            );
        }
    }

    #[test]
    fn request_size_and_unknown_file_modes_fail_closed() {
        let oversized = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            parse_run_request(&oversized),
            Err(RunSpecError::InputTooLarge)
        );
        let input = br#"{"version":1,"executable":"/usr/bin/curl","argv":[],"working_directory":"/workspace","file_access":[{"host_path":"/tmp/a","guest_path":"/workspace/a","mode":"write_only"}]}"#;
        assert_eq!(parse_run_request(input), Err(RunSpecError::InvalidRequest));
    }
}
