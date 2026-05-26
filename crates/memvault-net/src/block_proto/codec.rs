use async_trait::async_trait;
use futures::prelude::*;
use libp2p::StreamProtocol;
use std::io;

use super::{BlockRequest, BlockResponse};

/// Max message size: 16 MiB (blocks can be large for file chunks).
const MAX_MSG_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct BlockCodec;

#[async_trait]
impl libp2p::request_response::Codec for BlockCodec {
    type Protocol = StreamProtocol;
    type Request = BlockRequest;
    type Response = BlockResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as u64;
        if len > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        let mut buf = vec![0u8; len as usize];
        io.read_exact(&mut buf).await?;
        serde_ipld_dagcbor::from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as u64;
        if len > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut buf = vec![0u8; len as usize];
        io.read_exact(&mut buf).await?;
        serde_ipld_dagcbor::from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_ipld_dagcbor::to_vec(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_ipld_dagcbor::to_vec(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        Ok(())
    }
}
