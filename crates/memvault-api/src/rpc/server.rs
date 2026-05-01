//! Unix socket JSON-RPC server.

use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::client::MemvaultClient;
use crate::error::ApiError;

/// Start the JSON-RPC server on a Unix socket.
pub async fn serve(
    socket_path: &Path,
    client: Arc<dyn MemvaultClient>,
) -> Result<(), ApiError> {
    // Remove existing socket file
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("memvault RPC server listening on {:?}", socket_path);

    loop {
        let (stream, _) = listener.accept().await?;
        let client = Arc::clone(&client);

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let response = handle_request(&client, &line).await;
                        let mut resp_bytes = serde_json::to_vec(&response)
                            .unwrap_or_else(|_| b"{}".to_vec());
                        resp_bytes.push(b'\n');
                        if writer.write_all(&resp_bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

async fn handle_request(
    client: &Arc<dyn MemvaultClient>,
    line: &str,
) -> serde_json::Value {
    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": format!("Parse error: {e}")},
                "id": null
            });
        }
    };

    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(serde_json::json!({}));

    let result = dispatch(client, method, params).await;

    match result {
        Ok(value) => serde_json::json!({
            "jsonrpc": "2.0",
            "result": value,
            "id": id
        }),
        Err(e) => serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": e.to_string()},
            "id": id
        }),
    }
}

async fn dispatch(
    client: &Arc<dyn MemvaultClient>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    match method {
        "status" => {
            let status = client.status().await?;
            Ok(serde_json::to_value(status)
                .map_err(|e| ApiError::Serialization(e.to_string()))?)
        }
        "search" => {
            let query = params.get("query").and_then(|q| q.as_str()).unwrap_or("");
            let limit = params.get("limit").and_then(|l| l.as_u64()).unwrap_or(10) as usize;
            let hits = client.search(query, limit).await?;
            Ok(serde_json::to_value(hits)
                .map_err(|e| ApiError::Serialization(e.to_string()))?)
        }
        "list_rotations" => {
            let rotations = client.list_rotations().await?;
            Ok(serde_json::to_value(rotations)
                .map_err(|e| ApiError::Serialization(e.to_string()))?)
        }
        "list_tokens" => {
            let tokens = client.list_tokens().await?;
            Ok(serde_json::to_value(tokens)
                .map_err(|e| ApiError::Serialization(e.to_string()))?)
        }
        _ => Err(ApiError::Rpc(format!("unknown method: {method}"))),
    }
}
