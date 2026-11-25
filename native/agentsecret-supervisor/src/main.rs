use agentsecret_supervisor::docker_policy::compile_sbx_command_plan;
use agentsecret_supervisor::gateway::{
    self, GatewayConfig, GatewayError, GatewayOutcome, GatewayReceipt, Transport, TransportError,
    TransportRequest, TransportResponse,
};
use agentsecret_supervisor::{FileMode, StagingError, parse_run_request, stage_declared_files};
use serde_json::json;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const MAX_STDIN_BYTES: u64 = 64 * 1024;
const MAX_GATEWAY_STDIN_BYTES: u64 = 4 * 1024;
const MAX_CAPABILITY_FILE_BYTES: u64 = 512;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args_os().skip(1);
    let command = args.next();
    match command.as_deref() {
        Some(value) if value == OsStr::new("stage") => run_stage(args),
        Some(value) if value == OsStr::new("docker-plan") => run_docker_plan(args),
        Some(value) if value == OsStr::new("gateway") => run_gateway(args),
        Some(value) if value == OsStr::new("mcp") => run_mcp(args),
        Some(value) if value == OsStr::new("mcp-mediate") => run_mcp_mediate(args),
        _ => Err(
            "usage: agentsecret-supervisor stage --host-root PATH --destination PATH | docker-plan --host-root PATH --scratch PATH --sandbox-name NAME | gateway --broker-origin URL --capability-file PATH | mcp --self PATH --broker-origin URL --capability-file PATH | mcp-mediate --run-token-file PATH",
        ),
    }
}

fn read_gateway_request() -> Result<Vec<u8>, &'static str> {
    let mut input = Vec::with_capacity(MAX_GATEWAY_STDIN_BYTES as usize);
    io::stdin()
        .take(MAX_GATEWAY_STDIN_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| "gateway_request_read_failed")?;
    Ok(input)
}

/// Parse a bounded line-delimited JSON message from a trusted host pipe.
fn read_json_line(input: &mut impl BufRead) -> Result<Option<serde_json::Value>, &'static str> {
    let mut line = Vec::with_capacity(4096);
    let bytes = input
        .take(64 * 1024 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| "mcp_input_read_failed")?;
    if bytes == 0 {
        return Ok(None);
    }
    if bytes > 64 * 1024 {
        return Err("mcp_input_too_large");
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|_| "mcp_invalid_json")
}

/// Read a proxy capability from a host-private regular file.
///
/// The capability never travels through process arguments: registrations and
/// process listings would otherwise persist it. The file must be owned by the
/// invoking user's trust boundary, so group/other permissions are refused.
fn read_capability_file(path: &Path) -> Result<String, &'static str> {
    use rustix::fs::{Mode, OFlags, open};
    // Pin the descriptor before checking metadata. NONBLOCK prevents an
    // attacker-controlled FIFO from blocking before the regular-file check.
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            "capability_file_invalid"
        } else {
            "capability_file_unavailable"
        }
    })?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| "capability_file_unavailable")?;
    if !metadata.file_type().is_file() {
        return Err("capability_file_invalid");
    }
    if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("capability_file_permissions");
    }
    if metadata.len() > MAX_CAPABILITY_FILE_BYTES {
        return Err("capability_file_invalid");
    }
    let mut value = String::new();
    file.take(MAX_CAPABILITY_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|_| "capability_file_invalid")?;
    if value.len() > MAX_CAPABILITY_FILE_BYTES as usize {
        return Err("capability_file_invalid");
    }
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.len() > MAX_CAPABILITY_FILE_BYTES as usize {
        return Err("capability_file_invalid");
    }
    Ok(value.to_owned())
}

/// Blocking rustls transport for production gateway use.
struct ProductionTransport(gateway::UreqTransport);

impl ProductionTransport {
    fn new(timeout: std::time::Duration) -> Result<Self, &'static str> {
        Ok(Self(
            gateway::UreqTransport::new(timeout).map_err(|_| "gateway_transport_unavailable")?,
        ))
    }
}

impl Transport for ProductionTransport {
    fn send(&mut self, request: &TransportRequest) -> Result<TransportResponse, TransportError> {
        self.0.send(request)
    }
}

fn run_gateway(mut args: impl Iterator<Item = OsString>) -> Result<(), &'static str> {
    if args.next().as_deref() != Some(OsStr::new("--broker-origin")) {
        return Err("invalid_arguments");
    }
    let broker_origin = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--capability-file")) {
        return Err("invalid_arguments");
    }
    let capability_file = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().is_some() {
        return Err("invalid_arguments");
    }
    let capability = read_capability_file(&capability_file)?;
    let testing_origin =
        std::env::var_os("AGENTSECRET_GATEWAY_TESTING_ORIGIN").is_some_and(|value| value == "1");
    let config = if testing_origin {
        GatewayConfig::new_testing(&broker_origin).map_err(gateway_error_code)?
    } else {
        GatewayConfig::new(&broker_origin).map_err(gateway_error_code)?
    };
    let input = read_gateway_request()?;
    let request = gateway::parse_guest_request(&input).map_err(gateway_error_code)?;
    let mut transport = ProductionTransport::new(config.timeout)?;
    let receipt = gateway::redeem(&mut transport, &config, &capability, &request)
        .map_err(gateway_error_code)?;
    let output = write_gateway_receipt(&receipt)?;
    io::stdout()
        .write_all(&output)
        .map_err(|_| "gateway_result_write_failed")?;
    if receipt.outcome == GatewayOutcome::Unknown {
        return Err("gateway_execution_outcome_unknown");
    }
    Ok(())
}

fn run_mcp(mut args: impl Iterator<Item = OsString>) -> Result<(), &'static str> {
    if args.next().as_deref() != Some(OsStr::new("--self")) {
        return Err("invalid_arguments");
    }
    let self_path = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--broker-origin")) {
        return Err("invalid_arguments");
    }
    let broker_origin = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--capability-file")) {
        return Err("invalid_arguments");
    }
    let capability_file = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().is_some() {
        return Err("invalid_arguments");
    }
    let capability = read_capability_file(&capability_file)?;
    if !is_proxy_capability(&capability) {
        return Err("capability_file_invalid");
    }
    if self_path.as_os_str().is_empty() {
        return Err("invalid_arguments");
    }
    let testing_origin =
        std::env::var_os("AGENTSECRET_GATEWAY_TESTING_ORIGIN").is_some_and(|value| value == "1");
    if testing_origin {
        GatewayConfig::new_testing(&broker_origin).map_err(gateway_error_code)?;
    } else {
        GatewayConfig::new(&broker_origin).map_err(gateway_error_code)?;
    };

    let stdin = io::stdin();
    let mut input = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = stdout.lock();

    while let Some(message) = read_json_line(&mut input)? {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(serde_json::Value::as_str);
        let response = match method {
            Some("initialize") => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agentsecret-supervisor", "version": env!("CARGO_PKG_VERSION")}
                }
            })),
            Some("notifications/initialized") | Some("notifications/cancelled") => None,
            Some("tools/list") => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [{
                        "name": "proxy_http_request",
                        "description": "Perform one policy-authorized HTTPS request through the host supervisor.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "secret_alias": {"type": "string"},
                                "url": {"type": "string"},
                                "method": {"type": "string"},
                                "headers": {"type": "object"},
                                "body": {"type": "string"},
                            "response_mode": {"type": "string", "enum": ["git"]},
                            },
                            "required": ["secret_alias", "url", "method"],
                            "additionalProperties": false
                        }
                    }]
                }
            })),
            Some("tools/call") => {
                let params = message.get("params");
                let name = params
                    .and_then(|value| value.get("name"))
                    .and_then(serde_json::Value::as_str);
                if name != Some("proxy_http_request") {
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "unknown_tool"}
                    }))
                } else {
                    match invoke_gateway(
                        &self_path,
                        &broker_origin,
                        &capability_file,
                        params.and_then(|value| value.get("arguments")),
                    ) {
                        Ok(receipt) => Some(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": serde_json::to_string(&receipt).map_err(|_| "mcp_result_serialization_failed")?}],
                                "isError": receipt.outcome != GatewayOutcome::Known
                            }
                        })),
                        Err(code) => Some(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": -32603, "message": code}
                        })),
                    }
                }
            }
            Some(_) if id.is_some() => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method_not_found"}
            })),
            Some(_) => None,
            None if id.is_some() => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32600, "message": "invalid_request"}
            })),
            None => None,
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response).map_err(|_| "mcp_output_write_failed")?;
            output
                .write_all(b"\n")
                .map_err(|_| "mcp_output_write_failed")?;
            output.flush().map_err(|_| "mcp_output_write_failed")?;
        }
    }
    Ok(())
}

fn run_mcp_mediate(mut args: impl Iterator<Item = OsString>) -> Result<(), &'static str> {
    if args.next().as_deref() != Some(OsStr::new("--run-token-file")) {
        return Err("invalid_arguments");
    }
    let token_file = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().is_some() {
        return Err("invalid_arguments");
    }
    let origin =
        std::env::var("AGENTSECRET_MEDIATOR_ORIGIN").map_err(|_| "mediator_origin_unavailable")?;
    if !agentsecret_supervisor::is_local_mediator_origin(&origin) {
        return Err("mediator_origin_unsafe");
    }
    let tokens =
        agentsecret_supervisor::read_binding_file(token_file.to_str().ok_or("invalid_arguments")?)
            .map_err(|_| "sandbox_binding_file_invalid")?;

    let stdin = io::stdin();
    let mut input = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = stdout.lock();
    while let Some(message) = read_json_line(&mut input)? {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(serde_json::Value::as_str);
        let response = match method {
            Some("initialize") => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agentsecret-supervisor", "version": env!("CARGO_PKG_VERSION")}
                }
            })),
            Some("notifications/initialized") | Some("notifications/cancelled") => None,
            Some("tools/list") => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [{
                        "name": "proxy_http_request",
                        "description": "Perform one policy-authorized HTTPS request through the host mediator.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "secret_alias": {"type": "string"},
                                "url": {"type": "string"},
                                "method": {"type": "string"},
                                "headers": {"type": "object"},
                                "body": {"type": "string"},
                            "response_mode": {"type": "string", "enum": ["git"]},
                            },
                            "required": ["secret_alias", "url", "method"],
                            "additionalProperties": false
                        }
                    }]
                }
            })),
            Some("tools/call") => {
                let params = message.get("params");
                let name = params
                    .and_then(|value| value.get("name"))
                    .and_then(serde_json::Value::as_str);
                if name != Some("proxy_http_request") {
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "unknown_tool"}
                    }))
                } else {
                    match mediate_call(
                        &origin,
                        &tokens,
                        params.and_then(|value| value.get("arguments")),
                    ) {
                        Ok(receipt) => Some(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": receipt}],
                                "isError": false
                            }
                        })),
                        Err(code) => Some(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": -32603, "message": code}
                        })),
                    }
                }
            }
            Some(_) if id.is_some() => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method_not_found"}
            })),
            Some(_) => None,
            None if id.is_some() => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32600, "message": "invalid_request"}
            })),
            None => None,
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response).map_err(|_| "mcp_output_write_failed")?;
            output
                .write_all(b"\n")
                .map_err(|_| "mcp_output_write_failed")?;
            output.flush().map_err(|_| "mcp_output_write_failed")?;
        }
    }
    Ok(())
}

fn mediate_call(
    origin: &str,
    tokens: &[agentsecret_supervisor::RunBinding],
    arguments: Option<&serde_json::Value>,
) -> Result<String, &'static str> {
    let arguments = arguments.ok_or("gateway_request_invalid")?;
    let object = arguments.as_object().ok_or("gateway_request_invalid")?;
    // Refuse invalid or unsafe requests inside the guest-facing adapter. The
    // host mediator stays the authoritative enforcement point, but the guest
    // never causes a mediation attempt for a malformed/unsafe request. The MCP
    // argument names are mapped onto the gateway's closed raw-request shape.
    let mut raw = serde_json::Map::new();
    raw.insert(
        "alias".to_owned(),
        object
            .get("secret_alias")
            .cloned()
            .ok_or("gateway_request_invalid")?,
    );
    for key in ["url", "method", "headers", "body", "response_mode"] {
        if let Some(value) = object.get(key) {
            raw.insert(key.to_owned(), value.clone());
        }
    }
    let exact = gateway::parse_guest_request(
        &serde_json::to_vec(&serde_json::Value::Object(raw))
            .map_err(|_| "gateway_request_invalid")?,
    )
    .map_err(gateway_error_code)?;
    let alias = exact.secret_alias.clone();
    let token = tokens
        .iter()
        .find(|binding| binding.alias == alias)
        .ok_or("gateway_request_invalid")?;
    let request = json!({
        "run_token": token.token,
        "request": exact,
    });
    let bytes = serde_json::to_vec(&request).map_err(|_| "gateway_request_invalid")?;
    let mut transport = ProductionTransport::new(std::time::Duration::from_secs(20))?;
    let response = transport
        .send(&TransportRequest {
            url: format!("{origin}/mediate"),
            method: "POST".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: bytes,
        })
        .map_err(|_| "mediation_unavailable")?;
    if response.status != 200 {
        return Err("mediation_unavailable");
    }
    let body = String::from_utf8(response.body).map_err(|_| "mediation_invalid_response")?;
    serde_json::from_str::<serde_json::Value>(&body)
        .map(|_| body)
        .map_err(|_| "mediation_invalid_response")
}

fn invoke_gateway(
    self_path: &Path,
    broker_origin: &str,
    capability_file: &Path,
    arguments: Option<&serde_json::Value>,
) -> Result<GatewayReceipt, &'static str> {
    let arguments = arguments.ok_or("gateway_request_invalid")?;
    let object = arguments.as_object().ok_or("gateway_request_invalid")?;
    if object.len() < 3 || object.len() > 6 {
        return Err("gateway_request_invalid");
    }
    if !matches!(
        object.get("secret_alias"),
        Some(serde_json::Value::String(_))
    ) || !matches!(object.get("url"), Some(serde_json::Value::String(_)))
        || !matches!(object.get("method"), Some(serde_json::Value::String(_)))
    {
        return Err("gateway_request_invalid");
    }
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "secret_alias" | "url" | "method" | "headers" | "body" | "response_mode"
        )
    }) {
        return Err("gateway_request_invalid");
    }
    if object
        .get("headers")
        .is_some_and(|value| !value.is_object())
        || object.get("body").is_some_and(|value| !value.is_string())
        || object
            .get("response_mode")
            .is_some_and(|value| value.as_str() != Some("git"))
    {
        return Err("gateway_request_invalid");
    }
    let mut guest_request = serde_json::Map::new();
    guest_request.insert(
        "alias".to_owned(),
        arguments
            .get("secret_alias")
            .cloned()
            .ok_or("gateway_request_invalid")?,
    );
    guest_request.insert(
        "headers".to_owned(),
        arguments
            .get("headers")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
    );
    for key in ["url", "method", "body", "response_mode"] {
        if let Some(value) = arguments.get(key) {
            guest_request.insert(key.to_owned(), value.clone());
        }
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(guest_request))
        .map_err(|_| "gateway_request_invalid")?;
    if bytes.len() > 4 * 1024 {
        return Err("gateway_request_too_large");
    }
    let mut child = Command::new(self_path)
        .arg("gateway")
        .arg("--broker-origin")
        .arg(broker_origin)
        .arg("--capability-file")
        .arg(capability_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "gateway_execution_unavailable")?;
    child
        .stdin
        .take()
        .ok_or("gateway_execution_unavailable")?
        .write_all(&bytes)
        .map_err(|_| "gateway_request_write_failed")?;
    let output = child
        .wait_with_output()
        .map_err(|_| "gateway_execution_unavailable")?;
    let receipt = if output.status.success() && output.stderr.is_empty() {
        serde_json::from_slice::<GatewayReceipt>(&output.stdout)
            .map_err(|_| "gateway_result_invalid")?
    } else if output.status.success() {
        return Err("gateway_execution_failed");
    } else {
        let code = std::str::from_utf8(&output.stderr)
            .ok()
            .and_then(|value| value.lines().last())
            .unwrap_or("gateway_execution_failed");
        if code == "gateway_execution_outcome_unknown" {
            serde_json::from_slice::<GatewayReceipt>(&output.stdout)
                .map_err(|_| "gateway_result_invalid")?
        } else {
            return Err(match code {
                "gateway_request_too_large" => "gateway_request_too_large",
                "gateway_request_invalid_json" => "gateway_request_invalid_json",
                "gateway_request_invalid" => "gateway_request_invalid",
                "gateway_request_unsafe" => "gateway_request_unsafe",
                "gateway_broker_request_too_large" => "gateway_broker_request_too_large",
                "gateway_broker_response_too_large" => "gateway_broker_response_too_large",
                "gateway_outcome_unknown" => "gateway_outcome_unknown",
                "gateway_broker_invalid_response" => "gateway_broker_invalid_response",
                "capability_file_unavailable" => "capability_file_unavailable",
                "capability_file_permissions" => "capability_file_permissions",
                "capability_file_invalid" => "capability_file_invalid",
                _ => "gateway_execution_failed",
            });
        }
    };
    Ok(receipt)
}

fn is_proxy_capability(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("aspc1.") else {
        return false;
    };
    let mut parts = rest.splitn(2, '.');
    let tenant = parts.next().unwrap_or_default();
    let random = parts.next().unwrap_or_default();
    !tenant.is_empty()
        && tenant.len() <= 80
        && tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && random.len() == 43
        && random
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn write_gateway_receipt(receipt: &GatewayReceipt) -> Result<Vec<u8>, &'static str> {
    let mut output =
        serde_json::to_vec(receipt).map_err(|_| "gateway_result_serialization_failed")?;
    output.push(b'\n');
    Ok(output)
}

fn gateway_error_code(error: GatewayError) -> &'static str {
    match error {
        GatewayError::InputTooLarge => "gateway_request_too_large",
        GatewayError::InvalidJson => "gateway_request_invalid_json",
        GatewayError::InvalidRequest => "gateway_request_invalid",
        GatewayError::UnsafeRequest => "gateway_request_unsafe",
        GatewayError::LocalCompanionUnavailable => "local_companion_unavailable",
        GatewayError::BrokerRequestTooLarge => "gateway_broker_request_too_large",
        GatewayError::BrokerResponseTooLarge => "gateway_broker_response_too_large",
        GatewayError::BrokerOutcomeUnknown => "gateway_outcome_unknown",
        GatewayError::BrokerInvalidResponse => "gateway_broker_invalid_response",
        GatewayError::ExecutionOutcomeUnknown => "gateway_execution_outcome_unknown",
    }
}

fn read_run_request() -> Result<Vec<u8>, &'static str> {
    let mut input = Vec::with_capacity(MAX_STDIN_BYTES as usize);
    io::stdin()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| "run_request_read_failed")?;
    Ok(input)
}

fn parse_plan(input: &[u8]) -> Result<agentsecret_supervisor::ValidatedRunPlan, &'static str> {
    parse_run_request(input).map_err(|error| match error {
        agentsecret_supervisor::RunSpecError::InputTooLarge => "run_request_too_large",
        agentsecret_supervisor::RunSpecError::InvalidJson => "run_request_invalid_json",
        agentsecret_supervisor::RunSpecError::InvalidRequest => "run_request_invalid",
    })
}

fn run_stage(mut args: impl Iterator<Item = OsString>) -> Result<(), &'static str> {
    if args.next().as_deref() != Some(OsStr::new("--host-root")) {
        return Err("usage: agentsecret-supervisor stage --host-root PATH --destination PATH");
    }
    let host_root = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--destination")) {
        return Err("invalid_arguments");
    }
    let destination = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().is_some() {
        return Err("invalid_arguments");
    }

    let input = read_run_request()?;
    let plan = parse_plan(&input)?;
    let files = stage_declared_files(&plan, &host_root, &destination).map_err(staging_code)?;

    let result = json!({
        "schema": "agentsecret-supervisor/stage-result/v1",
        "files": files.iter().map(|file| json!({
            "guest_path": file.guest_path,
            "mode": match file.mode { FileMode::ReadOnly => "read_only", FileMode::ReadWrite => "read_write" },
            "byte_length": file.byte_length
        })).collect::<Vec<_>>()
    });
    write_result(&result, Some(&destination))
}

fn run_docker_plan(mut args: impl Iterator<Item = OsString>) -> Result<(), &'static str> {
    if args.next().as_deref() != Some(OsStr::new("--host-root")) {
        return Err(
            "usage: agentsecret-supervisor docker-plan --host-root PATH --scratch PATH --sandbox-name NAME",
        );
    }
    let host_root = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--scratch")) {
        return Err("invalid_arguments");
    }
    let scratch = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().as_deref() != Some(OsStr::new("--sandbox-name")) {
        return Err("invalid_arguments");
    }
    let sandbox_name = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("invalid_arguments")?;
    if args.next().is_some() {
        return Err("invalid_arguments");
    }

    let input = read_run_request()?;
    let plan = parse_plan(&input)?;
    // Reference bindings have no qualified mediation adapter yet; refuse before
    // staging so no workspace is created for a plan that cannot execute.
    if let Some(mediation) = &plan.mediation {
        if plan.reference_bindings.is_empty() {
            return Err("run_request_invalid");
        }
        let binding = agentsecret_supervisor::read_binding_file(&mediation.binding_file)
            .map_err(|_| "sandbox_binding_file_invalid")?;
        if !agentsecret_supervisor::binding_map_matches(&plan.reference_bindings, &binding) {
            return Err("sandbox_binding_file_invalid");
        }
        let env = agentsecret_supervisor::read_env_file(&mediation.env_file)
            .map_err(|_| "sandbox_binding_file_invalid")?;
        if !agentsecret_supervisor::env_map_matches(&plan.reference_bindings, &env) {
            return Err("sandbox_binding_file_invalid");
        }
    } else if !plan.reference_bindings.is_empty() {
        return Err("sandbox_secret_binding_unsupported");
    }
    let host_root = fs::canonicalize(&host_root).map_err(|_| "run_host_root_invalid")?;
    if !host_root.is_dir() {
        return Err("run_host_root_invalid");
    }

    // The scratch directory must not exist. Everything the plan needs lives
    // beneath it so the host runner can remove the whole run workspace after
    // the sandbox is gone.
    DirBuilder::new()
        .mode(0o700)
        .create(&scratch)
        .map_err(|_| "run_scratch_create_failed")?;
    let mut cleanup = RemovePath(scratch.clone());
    let scratch = fs::canonicalize(&scratch).map_err(|_| "run_scratch_invalid")?;
    cleanup.0 = scratch.clone();

    let primary = scratch.join("primary");
    let guest = scratch.join("guest");
    DirBuilder::new()
        .mode(0o700)
        .create(&primary)
        .map_err(|_| "run_workspace_invalid")?;
    DirBuilder::new()
        .mode(0o700)
        .create(&guest)
        .map_err(|_| "run_workspace_invalid")?;
    let staged_root = scratch.join("staged");

    let files = stage_declared_files(&plan, &host_root, &staged_root).map_err(staging_code)?;
    let command_plan = compile_sbx_command_plan(
        &plan,
        &sandbox_name,
        &primary,
        &guest,
        &staged_root,
        &files,
        &supervisor_path()?,
    )
    .map_err(docker_policy_code)?;

    let result = json!({
        "schema": "agentsecret-supervisor/docker-plan/v1",
        "sandbox_name": sandbox_name,
        "scratch": scratch,
        "host_environment_to_remove": command_plan.host_environment_to_remove,
        "global_credential_audit": command_plan.global_credential_audit,
        "sandbox_credential_audit": command_plan.sandbox_credential_audit,
        "account_policy_audit": command_plan.account_policy_audit,
        "create": command_plan.create,
        "sandbox_policy_audit": command_plan.sandbox_policy_audit,
        "allow_rules": command_plan.allow_rules,
        "verify_policy": command_plan.verify_policy,
        "execute": command_plan.execute,
        "mcp_add": command_plan.mcp_add,
        "mcp_load": command_plan.mcp_load,
        "mcp_unload": command_plan.mcp_unload,
        "mcp_remove": command_plan.mcp_remove,
        "remove": command_plan.remove,
        "staged_files": files.iter().map(|file| json!({
            "guest_path": file.guest_path,
            "mode": match file.mode { FileMode::ReadOnly => "read_only", FileMode::ReadWrite => "read_write" },
            "byte_length": file.byte_length
        })).collect::<Vec<_>>()
    });
    write_result(&result, Some(&scratch))?;
    cleanup.0 = PathBuf::new();
    Ok(())
}

fn supervisor_path() -> Result<PathBuf, &'static str> {
    std::env::current_exe()
        .map_err(|_| "supervisor_path_unavailable")
        .and_then(|path| {
            if path.is_file() && path.is_absolute() {
                Ok(path)
            } else {
                Err("supervisor_path_unavailable")
            }
        })
}

fn staging_code(error: StagingError) -> &'static str {
    match error {
        StagingError::InvalidWorkspace => "run_workspace_invalid",
        StagingError::DestinationAlreadyExists => "run_workspace_exists",
        StagingError::SourceOutsideWorkspace => "run_file_outside_workspace",
        StagingError::UnsafeSource => "run_file_unsafe",
        StagingError::FileTooLarge => "run_file_too_large",
        StagingError::TotalTooLarge => "run_files_total_too_large",
        StagingError::Io => "run_file_staging_failed",
    }
}

fn docker_policy_code(
    error: agentsecret_supervisor::docker_policy::DockerPolicyError,
) -> &'static str {
    use agentsecret_supervisor::docker_policy::DockerPolicyError as Code;
    match error {
        Code::InvalidSandboxName => "sandbox_name_invalid",
        Code::InvalidRule => "sandbox_egress_rule_invalid",
        Code::InvalidWorkspace => "sandbox_workspace_invalid",
        Code::InvalidStagedRoot => "sandbox_staged_root_invalid",
        Code::StagedFileMismatch => "sandbox_staged_file_mismatch",
        Code::SecretBindingUnsupported => "sandbox_secret_binding_unsupported",
    }
}

fn write_result(
    result: &serde_json::Value,
    cleanup_on_failure: Option<&Path>,
) -> Result<(), &'static str> {
    let mut output = serde_json::to_vec(result).map_err(|_| "run_result_serialization_failed")?;
    output.push(b'\n');
    if io::stdout().write_all(&output).is_err() {
        if let Some(path) = cleanup_on_failure {
            let _ = fs::remove_dir_all(path);
        }
        return Err("run_result_write_failed");
    }
    Ok(())
}

struct RemovePath(PathBuf);

impl Drop for RemovePath {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
