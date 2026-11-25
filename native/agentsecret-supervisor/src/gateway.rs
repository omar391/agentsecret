//! Outside-guest exact-request gateway and bounded transport contract.
//!
//! The guest never receives secret material. It sends a placeholder-bearing
//! request to this supervisor, which forwards the exact bytes to the broker's
//! single-use capability endpoint. Ambiguous outcomes are terminal: retries
//! could replay a hidden side effect and are never attempted here.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::time::Duration;

const MAX_GUEST_REQUEST_BYTES: usize = 4 * 1024;
const MAX_BROKER_REQUEST_BYTES: usize = 60 * 1024;
const MAX_BROKER_RESPONSE_BYTES: usize = 512 * 1024;
const SECRET_BODY_PLACEHOLDER: &str = "{{AGENTSECRET_SECRET}}";
const GIT_REQUEST_CONTENT_TYPES: &[&str] = &[
    "application/x-git-upload-pack-request",
    "application/x-git-receive-pack-request",
];

/// Closed static failure codes; they never contain request data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    InputTooLarge,
    InvalidJson,
    InvalidRequest,
    UnsafeRequest,
    LocalCompanionUnavailable,
    BrokerRequestTooLarge,
    BrokerResponseTooLarge,
    BrokerOutcomeUnknown,
    BrokerInvalidResponse,
    ExecutionOutcomeUnknown,
}

impl Display for GatewayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "gateway_request_too_large",
            Self::InvalidJson => "gateway_request_invalid_json",
            Self::InvalidRequest => "gateway_request_invalid",
            Self::UnsafeRequest => "gateway_request_unsafe",
            Self::LocalCompanionUnavailable => "local_companion_unavailable",
            Self::BrokerRequestTooLarge => "gateway_broker_request_too_large",
            Self::BrokerResponseTooLarge => "gateway_broker_response_too_large",
            Self::BrokerOutcomeUnknown => "gateway_outcome_unknown",
            Self::BrokerInvalidResponse => "gateway_broker_invalid_response",
            Self::ExecutionOutcomeUnknown => "gateway_execution_outcome_unknown",
        })
    }
}

impl std::error::Error for GatewayError {}

/// The transport's inbound request, deserialized only after size validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGuestRequest {
    alias: String,
    url: String,
    method: String,
    #[serde(default)]
    headers: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    response_mode: Option<ResponseMode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseMode {
    Git,
}

/// A validated, secret-free exact proxy request. `url` and `method` are
/// normalized exactly as the broker's `normalizeProxyRequest` does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExactProxyRequest {
    pub secret_alias: String,
    pub url: String,
    pub method: String,
    pub headers: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,
}

impl ExactProxyRequest {
    /// Serialize without changing key order, so the broker sees this exact JSON.
    ///
    /// # Errors
    /// Returns a static code when serialization or size validation fails.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, GatewayError> {
        let bytes = serde_json::to_vec(self).map_err(|_| GatewayError::InvalidRequest)?;
        if bytes.len() > MAX_BROKER_REQUEST_BYTES {
            return Err(GatewayError::BrokerRequestTooLarge);
        }
        Ok(bytes)
    }
}

/// The result returned to the guest or caller.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayReceipt {
    pub status: u16,
    pub outcome: GatewayOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Whether each side agrees on what happened.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOutcome {
    Known,
    Unknown,
}

/// Envelope returned by the broker after a one-use capability is redeemed.
#[derive(Debug, Deserialize)]
#[allow(
    dead_code,
    reason = "the wire contract keeps negotiated fields explicit"
)]
struct BrokerEnvelope {
    status: serde_json::Number,
    #[serde(default)]
    #[serde(rename = "redirectBlocked")]
    redirect_blocked: Option<bool>,
    #[serde(default)]
    headers: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(rename = "redactionsCount", default)]
    redactions_count: Option<serde_json::Number>,
    #[serde(rename = "requestDigest")]
    request_digest: Option<String>,
    #[serde(rename = "outcomeStatus")]
    outcome_status: Option<serde_json::Number>,
    #[serde(rename = "resultStatus")]
    result_status: Option<String>,
}

/// A bounded blocking HTTP transport. Production uses rustls with redirects,
/// proxies, decompression, cookies, and environment credential discovery disabled.
pub trait Transport {
    /// Send one request and return its status, headers, and bounded body.
    ///
    /// # Errors
    /// Implementations return a transport-specific error without retrying.
    fn send(&mut self, request: &TransportRequest) -> Result<TransportResponse, TransportError>;
}

/// A single outbound request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A bounded single response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Why a transport attempt ended without a trustworthy response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Network,
    Timeout,
    ResponseTooLarge,
    InvalidRedirect,
}

impl Display for TransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Network => "transport_network_error",
            Self::Timeout => "transport_timeout",
            Self::ResponseTooLarge => "transport_response_too_large",
            Self::InvalidRedirect => "transport_redirect_refused",
        })
    }
}

/// Blocking rustls transport with no redirects, proxy environment, cookies,
/// compression, stored credentials, or automatic retries.
#[derive(Debug)]
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// Create a transport for the given global timeout.
    ///
    /// # Errors
    /// Returns [TransportError::Network] if the rustls agent cannot be built.
    pub fn new(timeout: Duration) -> Result<Self, TransportError> {
        let agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .proxy(None)
            .build()
            .into();
        Ok(Self { agent })
    }
}

impl Transport for UreqTransport {
    fn send(&mut self, request: &TransportRequest) -> Result<TransportResponse, TransportError> {
        let mut builder = self.agent.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = builder
            .send(request.body.as_slice())
            .map_err(map_ureq_error)?;
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            if let Ok(value) = value.to_str() {
                headers.push((name.as_str().to_owned(), value.to_owned()));
            }
        }
        let body = response.into_parts().1;
        let bytes = read_bounded(body.into_reader(), MAX_BROKER_RESPONSE_BYTES)?;
        Ok(TransportResponse {
            status,
            headers,
            body: bytes,
        })
    }
}

fn map_ureq_error(error: ureq::Error) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::Io(error) => map_io_error(error),
        _ => TransportError::Network,
    }
}

fn map_io_error(error: std::io::Error) -> TransportError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        TransportError::Timeout
    } else {
        TransportError::Network
    }
}

/// Immutable gateway configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfig {
    pub broker_origin: String,
    pub timeout: Duration,
}

impl GatewayConfig {
    /// Create a configuration, validating the broker origin as HTTPS without
    /// userinfo, query, fragment, or a non-default port.
    ///
    /// # Errors
    /// Returns [GatewayError::UnsafeRequest] for a disallowed origin.
    pub fn new(broker_origin: &str) -> Result<Self, GatewayError> {
        if !is_https_origin(broker_origin) {
            return Err(GatewayError::UnsafeRequest);
        }
        Ok(Self {
            broker_origin: broker_origin.to_owned(),
            timeout: Duration::from_secs(20),
        })
    }

    /// For deterministic tests against a local stub broker.
    ///
    /// # Errors
    /// Returns [GatewayError::UnsafeRequest] for a disallowed origin.
    pub fn new_testing(broker_origin: &str) -> Result<Self, GatewayError> {
        if !is_local_http_origin(broker_origin) {
            return Err(GatewayError::UnsafeRequest);
        }
        Ok(Self {
            broker_origin: broker_origin.to_owned(),
            timeout: Duration::from_secs(20),
        })
    }

    fn capability_url(&self) -> String {
        format!("{}/proxy/capability", self.broker_origin)
    }
}

/// Parse and validate an untrusted guest request into an exact broker request.
///
/// # Errors
/// Returns a static code for every malformed or unsafe input.
pub fn parse_guest_request(input: &[u8]) -> Result<ExactProxyRequest, GatewayError> {
    if input.len() > MAX_GUEST_REQUEST_BYTES {
        return Err(GatewayError::InputTooLarge);
    }
    let raw: RawGuestRequest =
        serde_json::from_slice(input).map_err(|_| GatewayError::InvalidJson)?;
    validate_guest_request(raw)
}

fn validate_guest_request(raw: RawGuestRequest) -> Result<ExactProxyRequest, GatewayError> {
    if !is_broker_secret_alias(&raw.alias) || !is_supported_http_method(&raw.method) {
        return Err(GatewayError::InvalidRequest);
    }
    if !is_safe_https_url(&raw.url) {
        return Err(GatewayError::UnsafeRequest);
    }
    if raw.headers.len() > 32 {
        return Err(GatewayError::InvalidRequest);
    }
    let mut headers = serde_json::Map::new();
    for (name, value) in raw.headers {
        let value = value.as_str().ok_or(GatewayError::InvalidRequest)?;
        if is_reserved_http_header(&name)
            || is_unsupported_transport_header(&name)
            || !is_supported_http_header_name(&name)
            || !is_supported_http_header_value(value)
        {
            return Err(GatewayError::UnsafeRequest);
        }
        headers.insert(name, serde_json::Value::String(value.to_owned()));
    }
    let body = match raw.body {
        None => {
            if raw.method == "GET" || raw.method == "HEAD" {
                None
            } else {
                return Err(GatewayError::InvalidRequest);
            }
        }
        Some(body)
            if raw.response_mode == Some(ResponseMode::Git)
                && content_type(&headers)
                    .is_some_and(|value| GIT_REQUEST_CONTENT_TYPES.contains(&value.as_str()))
                && is_valid_git_request_body(&body) =>
        {
            Some(body)
        }
        Some(body)
            if matches!(
                content_type(&headers).as_deref(),
                Some("application/json" | "text/plain")
            ) && body.matches(SECRET_BODY_PLACEHOLDER).count() == 1
                && is_valid_utf8_no_control(&body) =>
        {
            Some(body)
        }
        Some(_) => return Err(GatewayError::InvalidRequest),
    };
    let request = ExactProxyRequest {
        secret_alias: raw.alias.to_ascii_uppercase(),
        url: raw.url,
        method: raw.method,
        headers,
        body,
        response_mode: raw.response_mode,
    };
    request.to_wire_bytes()?;
    Ok(request)
}

fn is_reserved_http_header(value: &str) -> bool {
    value.eq_ignore_ascii_case("authorization")
        || value.eq_ignore_ascii_case("proxy-authorization")
        || value.eq_ignore_ascii_case("cookie")
        || value.eq_ignore_ascii_case("host")
        || value.eq_ignore_ascii_case("connection")
        || value.eq_ignore_ascii_case("content-length")
        || value.eq_ignore_ascii_case("transfer-encoding")
        || value.eq_ignore_ascii_case("forwarded")
        || value.eq_ignore_ascii_case("x-api-key")
        || value.eq_ignore_ascii_case("api-key")
        || (value.eq_ignore_ascii_case("x-forwarded-host")
            || value.eq_ignore_ascii_case("x-forwarded-for")
            || value.eq_ignore_ascii_case("x-forwarded-proto")
            || value.eq_ignore_ascii_case("x-forwarded-port"))
        || (value.to_ascii_lowercase().starts_with("cf-") && value.len() >= 3)
        || (value.to_ascii_lowercase().starts_with("sec-") && value.len() >= 4)
}

fn is_unsupported_transport_header(value: &str) -> bool {
    value.eq_ignore_ascii_case("keep-alive")
        || value.eq_ignore_ascii_case("proxy-connection")
        || value.eq_ignore_ascii_case("proxy-authenticate")
        || value.eq_ignore_ascii_case("te")
        || value.eq_ignore_ascii_case("trailer")
        || value.eq_ignore_ascii_case("upgrade")
        || value.eq_ignore_ascii_case("expect")
}

/// Redeem a capability exactly once and return a non-secret receipt.
///
/// # Errors
/// Network/timeout failures are ambiguous terminal outcomes; structural broker
/// errors are known failures. Neither path retries.
pub fn redeem<T: Transport>(
    transport: &mut T,
    config: &GatewayConfig,
    capability: &str,
    request: &ExactProxyRequest,
) -> Result<GatewayReceipt, GatewayError> {
    if !is_proxy_capability(capability) {
        return Err(GatewayError::InvalidRequest);
    }
    let wire = request.to_wire_bytes()?;
    let transport_request = TransportRequest {
        url: config.capability_url(),
        method: "POST".to_owned(),
        headers: vec![
            (
                "authorization".to_owned(),
                format!("AgentSecret {capability}"),
            ),
            ("content-type".to_owned(), "application/json".to_owned()),
        ],
        body: wire,
    };
    let response = transport
        .send(&transport_request)
        .map_err(|error| match error {
            TransportError::Network => GatewayError::BrokerOutcomeUnknown,
            TransportError::Timeout => GatewayError::BrokerOutcomeUnknown,
            TransportError::ResponseTooLarge => GatewayError::BrokerResponseTooLarge,
            TransportError::InvalidRedirect => GatewayError::BrokerInvalidResponse,
        })?;
    finish_broker_response(response)
}

fn finish_broker_response(response: TransportResponse) -> Result<GatewayReceipt, GatewayError> {
    if (300..400).contains(&response.status) {
        return Err(GatewayError::BrokerInvalidResponse);
    }
    if response.body.len() > MAX_BROKER_RESPONSE_BYTES {
        return Err(GatewayError::BrokerResponseTooLarge);
    }
    let envelope: BrokerEnvelope =
        serde_json::from_slice(&response.body).map_err(|_| GatewayError::BrokerInvalidResponse)?;
    let Some(status) = number_as_u16(&envelope.status) else {
        return Err(GatewayError::BrokerInvalidResponse);
    };
    if envelope.redirect_blocked == Some(true) {
        return Ok(GatewayReceipt {
            status,
            outcome: GatewayOutcome::Known,
            data: None,
        });
    }
    if envelope.outcome_status.as_ref().and_then(number_as_u16) == Some(0) {
        return Ok(GatewayReceipt {
            status,
            outcome: GatewayOutcome::Known,
            data: envelope.data,
        });
    }
    if envelope.result_status.as_deref() == Some("unknown") {
        return Ok(GatewayReceipt {
            status,
            outcome: GatewayOutcome::Unknown,
            data: None,
        });
    }
    if (200..400).contains(&status) {
        return Ok(GatewayReceipt {
            status,
            outcome: GatewayOutcome::Known,
            data: envelope.data,
        });
    }
    Ok(GatewayReceipt {
        status,
        outcome: GatewayOutcome::Unknown,
        data: None,
    })
}

/// Fail closed: there is no qualified direct local-companion resolver.
///
/// Cloud-provider authorization and value resolution stay authoritative. A
/// local-only fallback must go through the broker's exact-request capability
/// contract; it must never resolve values directly on the host.
///
/// # Errors
/// Every call returns [GatewayError::LocalCompanionUnavailable].
pub fn local_companion_resolve() -> Result<GatewayReceipt, GatewayError> {
    Err(GatewayError::LocalCompanionUnavailable)
}

/// Mediate a local-companion-backed request through the authorized broker.
///
/// Local companion providers keep their values outside the cloud, so the owner
/// authorizes the same exact request shape, the host obtains a one-use broker
/// capability, and the broker's existing companion flow resolves and injects
/// the value while this gateway preserves the exact request bytes and refuses
/// retries. This reuses the normal capability contract rather than defining a
/// parallel local ticket format.
///
/// # Errors
/// Returns a static code for malformed input or terminal broker outcomes.
pub fn local_companion_mediate<T: Transport>(
    transport: &mut T,
    config: &GatewayConfig,
    capability: &str,
    request: &ExactProxyRequest,
) -> Result<GatewayReceipt, GatewayError> {
    redeem(transport, config, capability, request)
}

/// Read an exact number of bytes from a body, refusing a larger response.
///
/// # Errors
/// Returns [TransportError::ResponseTooLarge] when the stream exceeds `limit`.
pub fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let count = reader.read(&mut chunk).map_err(map_io_error)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > limit {
            return Err(TransportError::ResponseTooLarge);
        }
    }
    Ok(bytes)
}

fn is_broker_secret_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_supported_http_method(value: &str) -> bool {
    matches!(
        value,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

fn is_https_origin(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let path = rest.split_once('/').map(|(_, path)| path);
    path.is_none_or(|path| path.is_empty())
}

fn is_local_http_origin(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    match name {
        "127.0.0.1" => {}
        "localhost" => {}
        "[::1]" => {}
        _ => return false,
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    let path = rest.split_once('/').map(|(_, path)| path);
    path.is_none_or(|path| path.is_empty())
}

fn is_safe_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    if rest.len() > 4096 || rest.contains('@') || rest.contains('#') {
        return false;
    }
    let (authority, path_and_query) = match rest.split_once('/') {
        Some((authority, rest)) => (authority, rest),
        None => (rest, ""),
    };
    if authority.contains(':') {
        return false;
    }
    let path = path_and_query.split('?').next().unwrap_or_default();
    if path.is_empty() {
        return true;
    }
    true && !path
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, 0..=0x1f | 0x7f))
        && !path.contains("//")
        && !path.split('/').any(|part| part == "." || part == "..")
        && !path.to_ascii_lowercase().contains("%2f")
        && !path.to_ascii_lowercase().contains("%5c")
        && !path.to_ascii_lowercase().contains("%2e")
        && !path.to_ascii_lowercase().contains("%25")
}

fn is_supported_http_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_supported_http_header_value(value: &str) -> bool {
    value == value.trim()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn content_type(headers: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| value.as_str())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
}

/// Git smart-HTTP request bodies are pkt-line text: printable ASCII plus the
/// TAB/LF/CR separators the wire format uses between records. Every other
/// control byte and DEL is refused; binary pack data cannot cross this
/// contract, which also keeps receive-pack uploads fail-closed.
fn is_valid_git_request_body(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| matches!(byte, 0..=0x1f | 0x7f) && !matches!(byte, b'\t' | b'\n' | b'\r'))
}

fn is_valid_utf8_no_control(value: &str) -> bool {
    std::str::from_utf8(value.as_bytes()).is_ok()
        && !value
            .bytes()
            .any(|byte| matches!(byte, 0..=0x1f | 0x7f) && byte != b'\t')
}

fn is_proxy_capability(value: &str) -> bool {
    let mut parts = value.split('.');
    parts.next() == Some("aspc1")
        && parts.next().is_some_and(|part| {
            (1..=80).contains(&part.len())
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && parts.next().is_some_and(|part| {
            (32..=128).contains(&part.len())
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && parts.next().is_none()
}

fn number_as_u16(value: &serde_json::Number) -> Option<u16> {
    value.as_u64()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_request(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn parses_and_normalizes_a_safe_exact_request() {
        let request = parse_guest_request(&valid_request(json!({
            "alias": "GitHubToken",
            "url": "https://api.github.com/repos/example/example",
            "method": "GET",
            "headers": {"accept": "application/vnd.github+json"}
        })))
        .unwrap();
        assert_eq!(request.secret_alias, "GITHUBTOKEN");
        assert_eq!(request.method, "GET");
        assert!(request.body.is_none());
    }

    #[test]
    fn git_bodies_allow_pkt_line_separators_but_no_other_controls() {
        let git = |body: &str| {
            valid_request(json!({
                "alias": "GIT_TOKEN",
                "url": "https://git.example.com/repo.git/git-upload-pack",
                "method": "POST",
                "headers": {"content-type": "application/x-git-upload-pack-request"},
                "body": body,
                "response_mode": "git"
            }))
        };
        let request =
            parse_guest_request(&git("0014command=fetch\n0001000cdeepen 1\n0000")).unwrap();
        assert_eq!(request.response_mode, Some(ResponseMode::Git));
        for body in [
            "0014command=fetch\n\u{0}binary",
            "0014command=fetch\u{7}",
            "\u{1f}0014command=fetch\n",
        ] {
            assert_eq!(
                parse_guest_request(&git(body)),
                Err(GatewayError::InvalidRequest),
                "control byte must be refused: {body:?}"
            );
        }
        // The same body without response_mode=git must not reach the broker.
        let plain = valid_request(json!({
            "alias": "GIT_TOKEN",
            "url": "https://git.example.com/repo.git/git-upload-pack",
            "method": "POST",
            "headers": {"content-type": "application/x-git-upload-pack-request"},
            "body": "0014command=fetch\n0000"
        }));
        assert_eq!(
            parse_guest_request(&plain),
            Err(GatewayError::InvalidRequest)
        );
        // Git mode with a non-git content type stays fail-closed.
        let wrong_type = valid_request(json!({
            "alias": "GIT_TOKEN",
            "url": "https://git.example.com/repo.git/git-upload-pack",
            "method": "POST",
            "headers": {"content-type": "application/json"},
            "body": "0014command=fetch\n0000",
            "response_mode": "git"
        }));
        assert_eq!(
            parse_guest_request(&wrong_type),
            Err(GatewayError::InvalidRequest)
        );
    }

    #[test]
    fn body_placeholder_is_required_and_single_use() {
        let request = parse_guest_request(&valid_request(json!({
            "alias": "API_TOKEN",
            "url": "https://api.example.com/v1/check",
            "method": "POST",
            "headers": {"content-type": "application/json"},
            "body": "{\"credential\":\"{{AGENTSECRET_SECRET}}\"}"
        })))
        .unwrap();
        assert!(
            request
                .body
                .as_deref()
                .is_some_and(|body| body.contains("{{AGENTSECRET_SECRET}}"))
        );
        let twice = json!({
            "alias": "API_TOKEN",
            "url": "https://api.example.com/v1/check",
            "method": "POST",
            "headers": {"content-type": "application/json"},
            "body": "{{AGENTSECRET_SECRET}}{{AGENTSECRET_SECRET}}"
        });
        assert_eq!(
            parse_guest_request(&valid_request(twice)),
            Err(GatewayError::InvalidRequest)
        );
        let no_placeholder = json!({
            "alias": "API_TOKEN",
            "url": "https://api.example.com/v1/check",
            "method": "POST",
            "headers": {"content-type": "application/json"},
            "body": "{}"
        });
        assert_eq!(
            parse_guest_request(&valid_request(no_placeholder)),
            Err(GatewayError::InvalidRequest)
        );
    }

    #[test]
    fn refuses_unsafe_urls_headers_and_unknown_fields() {
        for url in [
            "http://api.example.com",
            "https://user@api.example.com",
            "https://api.example.com:8443/x",
            "https://api.example.com/x#frag",
            "https://api.example.com/../x",
            "https://api.example.com/%2e%2e/x",
        ] {
            let request = json!({
                "alias": "API_TOKEN", "url": url, "method": "GET", "headers": {}
            });
            assert_eq!(
                parse_guest_request(&valid_request(request)),
                Err(GatewayError::UnsafeRequest),
                "url must be refused: {url}"
            );
        }
        let reserved = json!({
            "alias": "API_TOKEN",
            "url": "https://api.example.com",
            "method": "GET",
            "headers": {"authorization": "Bearer leaked"}
        });
        assert_eq!(
            parse_guest_request(&valid_request(reserved)),
            Err(GatewayError::UnsafeRequest)
        );
        let unknown = br#"{"alias":"A","url":"https://a.example.com","method":"GET","headers":{},"secret":"x"}"#;
        assert_eq!(parse_guest_request(unknown), Err(GatewayError::InvalidJson));
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let input = vec![b' '; MAX_GUEST_REQUEST_BYTES + 1];
        assert_eq!(
            parse_guest_request(&input),
            Err(GatewayError::InputTooLarge)
        );
    }

    #[test]
    fn local_companion_is_fail_closed_until_qualified() {
        assert_eq!(
            local_companion_resolve(),
            Err(GatewayError::LocalCompanionUnavailable)
        );
    }

    #[test]
    fn local_companion_mediation_reuses_the_exact_capability_contract_once() {
        let mut transport = StubTransport::default();
        let config = GatewayConfig::new_testing("http://127.0.0.1/").unwrap();
        let request = ExactProxyRequest {
            secret_alias: "LOCAL_ONLY".to_owned(),
            url: "https://api.example.com/v1".to_owned(),
            method: "GET".to_owned(),
            headers: serde_json::Map::new(),
            body: None,
            response_mode: None,
        };
        transport.next = Some(Ok(TransportResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"status":200,"outcomeStatus":0,"data":{"ok":true}}"#.to_vec(),
        }));
        assert_eq!(
            local_companion_mediate(
                &mut transport,
                &config,
                "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
                &request,
            ),
            Ok(GatewayReceipt {
                status: 200,
                outcome: GatewayOutcome::Known,
                data: Some(json!({"ok": true})),
            })
        );
        assert_eq!(transport.calls.len(), 1);

        transport.next = Some(Err(TransportError::Timeout));
        assert_eq!(
            local_companion_mediate(
                &mut transport,
                &config,
                "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
                &request,
            ),
            Err(GatewayError::BrokerOutcomeUnknown)
        );
        assert_eq!(transport.calls.len(), 2);
    }

    #[test]
    fn bounded_transport_preserves_exact_bytes_and_refuses_oversized_responses() {
        let bytes: Vec<u8> = [0u8, 1, 2, 250, 255, 10, 13]
            .into_iter()
            .cycle()
            .take(1024)
            .collect();
        let cursor = std::io::Cursor::new(bytes.clone());
        assert_eq!(read_bounded(cursor, 1024).unwrap(), bytes);

        let cursor = std::io::Cursor::new(vec![0u8; 513]);
        assert_eq!(
            read_bounded(cursor, 512),
            Err(TransportError::ResponseTooLarge)
        );
    }

    #[test]
    fn accepts_only_exact_origin_forms() {
        assert!(is_https_origin("https://broker.example.com"));
        assert!(is_https_origin("https://broker.example.com/"));
        assert!(!is_https_origin("https://broker.example.com/path"));
        assert!(!is_https_origin("http://broker.example.com"));
        assert!(is_local_http_origin("http://127.0.0.1"));
        assert!(is_local_http_origin("http://127.0.0.1/"));
        assert!(is_local_http_origin("http://127.0.0.1:12345/"));
        assert!(is_local_http_origin("http://127.0.0.1:1234"));
        assert!(!is_local_http_origin("https://127.0.0.1"));
    }

    #[test]
    fn broker_receipt_boundaries_are_terminal() {
        let mut transport = StubTransport::default();
        let config = GatewayConfig::new_testing("http://127.0.0.1/").unwrap();
        let request = ExactProxyRequest {
            secret_alias: "API_TOKEN".to_owned(),
            url: "https://api.example.com/v1".to_owned(),
            method: "GET".to_owned(),
            headers: serde_json::Map::new(),
            body: None,
            response_mode: None,
        };
        transport.next = Some(Ok(TransportResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"status":200,"data":{"ok":true}}"#.to_vec(),
        }));
        assert_eq!(
            redeem(
                &mut transport,
                &config,
                "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
                &request
            ),
            Ok(GatewayReceipt {
                status: 200,
                outcome: GatewayOutcome::Known,
                data: Some(json!({"ok": true})),
            })
        );

        transport.next = Some(Err(TransportError::Network));
        assert_eq!(
            redeem(
                &mut transport,
                &config,
                "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
                &request
            ),
            Err(GatewayError::BrokerOutcomeUnknown)
        );
        assert_eq!(
            transport.calls.len(),
            2,
            "the two assertions make exactly one call each and never retry"
        );

        transport.next = Some(Ok(TransportResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"status":302,"redirectBlocked":true,"data":null}"#.to_vec(),
        }));
        assert_eq!(
            redeem(
                &mut transport,
                &config,
                "aspc1.tenant.abcdefghijklmnopqrstuvwxyz012345",
                &request
            )
            .unwrap()
            .outcome,
            GatewayOutcome::Known
        );
    }

    #[derive(Default)]
    struct StubTransport {
        next: Option<Result<TransportResponse, TransportError>>,
        calls: Vec<TransportRequest>,
    }

    impl Transport for StubTransport {
        fn send(
            &mut self,
            request: &TransportRequest,
        ) -> Result<TransportResponse, TransportError> {
            self.calls.push(request.clone());
            self.next.take().unwrap_or(Err(TransportError::Network))
        }
    }
}
