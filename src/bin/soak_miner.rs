use arkos::blockchain::block::BlockHeader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Template {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    timestamp: u64,
    bits: u32,
    height: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitParams {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    timestamp: u64,
    bits: u32,
    nonce: u64,
    wallet_address: String,
    height: u64,
}

fn rpc(addr: &str, token: &str, method: &str, params: Value) -> anyhow::Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let request = format!(
        "POST /rpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (_, json_body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?;
    let envelope: Value = serde_json::from_str(json_body)?;
    if let Some(error) = envelope.get("error") {
        anyhow::bail!("RPC {method} error: {error}");
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("RPC {method} response missing result"))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        anyhow::bail!(
            "usage: soak_miner <template-rpc-host:port> <token> <wallet-address> [submit-rpc-host:port ...]"
        );
    }

    let addr = &args[1];
    let token = &args[2];
    let wallet_address = &args[3];
    let submit_addrs: Vec<&str> = if args.len() > 4 {
        args[4..].iter().map(String::as_str).collect()
    } else {
        vec![addr.as_str()]
    };

    let template_value = rpc(
        addr,
        token,
        "getBlockTemplate",
        json!({ "walletAddress": wallet_address }),
    )?;
    let template: Template = serde_json::from_value(template_value)?;
    let mut header = BlockHeader {
        version: template.version,
        prev_hash: template.prev_hash.clone(),
        merkle_root: template.merkle_root.clone(),
        timestamp: template.timestamp,
        bits: template.bits,
        nonce: 0,
    };

    while !header.meets_target() {
        header.nonce = header.nonce.wrapping_add(1);
        if header.nonce == 0 {
            header.timestamp += 1;
        }
    }

    let hash = header.hash_hex();
    let mut results = Vec::new();
    for submit_addr in submit_addrs {
        let submit = SubmitParams {
            version: template.version,
            prev_hash: template.prev_hash.clone(),
            merkle_root: template.merkle_root.clone(),
            timestamp: header.timestamp,
            bits: template.bits,
            nonce: header.nonce,
            wallet_address: wallet_address.to_string(),
            height: template.height,
        };
        let result = match rpc(
            submit_addr,
            token,
            "submitBlock",
            serde_json::to_value(submit)?,
        ) {
            Ok(result) => json!({ "rpc": submit_addr, "ok": true, "result": result }),
            Err(e) => json!({ "rpc": submit_addr, "ok": false, "error": e.to_string() }),
        };
        results.push(result);
    }
    println!(
        "{}",
        json!({
            "submittedHash": hash,
            "results": results,
        })
    );
    Ok(())
}
