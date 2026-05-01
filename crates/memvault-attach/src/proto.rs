//! Protobuf types for DAG-PB and UnixFS.

/// DAG-PB Link.
#[derive(Clone, prost::Message)]
pub struct PbLink {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub hash: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    pub name: Option<String>,
    #[prost(uint64, optional, tag = "3")]
    pub tsize: Option<u64>,
}

/// DAG-PB Node.
#[derive(Clone, prost::Message)]
pub struct PbNode {
    /// UnixFS data payload (encoded UnixFsData).
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
    /// Links to children.
    #[prost(message, repeated, tag = "2")]
    pub links: Vec<PbLink>,
}

/// UnixFS Data (embedded in PbNode.data).
#[derive(Clone, prost::Message)]
pub struct UnixFsData {
    #[prost(enumeration = "DataType", tag = "1")]
    pub r#type: i32,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "3")]
    pub filesize: Option<u64>,
    #[prost(uint64, repeated, tag = "4")]
    pub blocksizes: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum DataType {
    Raw = 0,
    Directory = 1,
    File = 2,
}
