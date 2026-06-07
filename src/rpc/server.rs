//! Axum HTTP server exposing the Arkos JSON-RPC 2.0 API.
//!
//! All requests are `POST /rpc` with a JSON body:
//! ```json
//! { "jsonrpc": "2.0", "id": 1, "method": "getBlockTemplate",
//!   "params": { "walletAddress": "abc..." } }
//! ```
//!
//! Responses follow JSON-RPC 2.0:
//! ```json
//! { "jsonrpc": "2.0", "id": 1, "result": { ... } }
//! { "jsonrpc": "2.0", "id": 1, "error": { "code": -32600, "message": "..." } }
//! ```

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use super::methods::{handle, RpcRequest, RpcState};

#[derive(Debug, Clone, Default)]
pub struct RpcServerConfig {
    pub auth_token: Option<String>,
    pub cors_origin: Option<String>,
}

#[derive(Clone)]
struct ServerState {
    rpc: Arc<RpcState>,
    config: RpcServerConfig,
}

// ─── JSON-RPC 2.0 envelope ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    fn ok(id: Option<Value>, result: impl Serialize) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::to_value(result).unwrap_or(json!(null))),
            error: None,
        }
    }

    fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: Arc<RpcState>, config: RpcServerConfig) -> anyhow::Result<Router> {
    let allow_origin = match &config.cors_origin {
        Some(origin) => AllowOrigin::exact(HeaderValue::from_str(origin)?),
        // Default to loopback-only CORS, not wildcard.  Wildcard would allow any
        // web page on the internet to issue authenticated RPC calls from a user's
        // browser session.
        None => AllowOrigin::exact(HeaderValue::from_static("http://127.0.0.1")),
    };
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(Any)
        .allow_headers(Any);

    let server_state = Arc::new(ServerState { rpc: state, config });

    Ok(Router::new()
        .route("/rpc", post(rpc_handler))
        .route("/health", axum::routing::get(health_handler))
        .layer(cors)
        .with_state(server_state))
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok", "chain": "arkos" }))
}

/// Dispatch a JSON-RPC 2.0 request.
async fn rpc_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(envelope): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = envelope.id.clone();

    // Version check
    if envelope.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(JsonRpcResponse::err(id, -32600, "jsonrpc must be '2.0'")),
        );
    }

    if !authorized(&headers, state.config.auth_token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(JsonRpcResponse::err(id, -32001, "unauthorized")),
        );
    }

    // Parse the structured request using method + params
    let rpc_req = match parse_request(&envelope.method, envelope.params) {
        Ok(r) => r,
        Err(msg) => {
            return (StatusCode::OK, Json(JsonRpcResponse::err(id, -32601, msg)));
        }
    };

    // Dispatch
    match handle(state.rpc.clone(), rpc_req).await {
        Ok(result) => (StatusCode::OK, Json(JsonRpcResponse::ok(id, result))),
        Err(msg) => (StatusCode::OK, Json(JsonRpcResponse::err(id, -32000, msg))),
    }
}

/// Constant-time token comparison — prevents timing oracle attacks.
/// Two byte slices of different length compare as unequal without
/// revealing the length of the expected token.
fn ct_eq_tokens(a: &str, b: &str) -> bool {
    // Pad to same length in constant time: if lengths differ the result is
    // always 0 (false), but we still run the comparison loop.
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        // Still do a constant-time comparison of the first min(a,b) bytes
        // so the timing is not trivially distinguishable by length alone.
        let min_len = a.len().min(b.len());
        let _ = a[..min_len].ct_eq(&b[..min_len]);
        return false;
    }
    a.ct_eq(b).into()
}

fn authorized(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };

    let bearer_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| ct_eq_tokens(token, expected))
        .unwrap_or(false);

    let header_ok = headers
        .get("x-arkos-rpc-token")
        .and_then(|value| value.to_str().ok())
        .map(|token| ct_eq_tokens(token, expected))
        .unwrap_or(false);

    bearer_ok || header_ok
}

/// Convert a (method, params) pair into a typed `RpcRequest`.
fn parse_request(method: &str, params: Option<Value>) -> Result<RpcRequest, String> {
    let params = params.unwrap_or(Value::Null);

    let req = match method {
        "getBlockTemplate" => {
            let p = serde_json::from_value(params)
                .map_err(|e| format!("bad params for getBlockTemplate: {}", e))?;
            RpcRequest::GetBlockTemplate(p)
        }
        "submitBlock" => {
            let p = serde_json::from_value(params)
                .map_err(|e| format!("bad params for submitBlock: {}", e))?;
            RpcRequest::SubmitBlock(p)
        }
        "getBalance" => {
            let p = serde_json::from_value(params)
                .map_err(|e| format!("bad params for getBalance: {}", e))?;
            RpcRequest::GetBalance(p)
        }
        "getBlockCount" => RpcRequest::GetBlockCount,
        "getMiningInfo" => RpcRequest::GetMiningInfo,
        other => return Err(format!("unknown method '{}'", other)),
    };

    Ok(req)
}

// ─── Start helper ─────────────────────────────────────────────────────────────

pub async fn start_rpc_server(
    state: Arc<RpcState>,
    addr: &str,
    config: RpcServerConfig,
) -> anyhow::Result<()> {
    // Warn if binding to a non-loopback interface — the RPC endpoint carries
    // financial operations and should never be accidentally exposed publicly.
    let host = addr.split(':').next().unwrap_or("");
    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        log::warn!(
            "RPC server is binding to a non-loopback address: {}. \
             Ensure this is intentional and the port is firewalled.",
            addr
        );
    }

    let app = router(state, config)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("Arkos RPC server listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn rpc_auth_accepts_bearer_or_custom_header() {
        let mut headers = HeaderMap::new();
        assert!(authorized(&headers, None));
        assert!(!authorized(&headers, Some("secret")));

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(authorized(&headers, Some("secret")));

        headers.clear();
        headers.insert("x-arkos-rpc-token", HeaderValue::from_static("secret"));
        assert!(authorized(&headers, Some("secret")));
    }
}
