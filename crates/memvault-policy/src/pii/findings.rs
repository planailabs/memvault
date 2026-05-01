use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PiiKind {
    Email,
    Phone,
    Ssn,
    CreditCard,
    PersonName,
    StreetAddress,
    IpAddress,
    Iban,
    DateOfBirth,
    HealthRecordNumber,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub kind: PiiKind,
    pub location: Location,
    pub text: String,
    pub confidence: f32,
    pub detector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub byte_offset: usize,
    pub byte_length: usize,
}
