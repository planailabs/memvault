//! RPC client connecting to the Unix socket.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::ApiError;

/// RPC client that connects to the Unix socket.
pub struct RpcClient {
    socket_path: PathBuf,
}

impl RpcClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Call a JSON-RPC method.
    pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        method: &str,
        params: Req,
    ) -> Result<Resp, ApiError> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (reader, mut writer) = stream.into_split();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let mut req_bytes =
            serde_json::to_vec(&request).map_err(|e| ApiError::Serialization(e.to_string()))?;
        req_bytes.push(b'\n');
        writer.write_all(&req_bytes).await?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let resp: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| ApiError::Serialization(e.to_string()))?;

        if let Some(error) = resp.get("error") {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(ApiError::Rpc(msg.to_string()));
        }

        let result = resp
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        serde_json::from_value(result).map_err(|e| ApiError::Serialization(e.to_string()))
    }
}
