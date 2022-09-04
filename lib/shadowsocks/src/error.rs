use std::io;

use resolver::ResolveError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

/// AEAD protocol error
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("packet too short, at least {0} bytes, but found {1} bytes")]
    PacketTooShort(usize, usize),
    #[error("invalid socket type, expecting {0:#x}, but found {1:#x}")]
    InvalidSocketType(u8, u8),
    #[error("invalid timestamp {0} - now {1} = {}", *.0 as i64 - *.1 as i64)]
    InvalidTimestamp(u64, u64),

    #[error("packet too short for salt, at least {0} bytes, but only got {1} bytes")]
    PacketTooShortForSalt(usize, usize),
    #[error("packet too short for tag, at least {0} bytes, but only got {1} bytes")]
    PacketTooShortForTag(usize, usize),
    #[error("decrypt payload failed")]
    DecryptPayloadError,
    #[error("decrypt length failed")]
    DecryptLengthError,
    #[error("buffer size too large ({0:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero")]
    DataTooLong(usize),

    // Address
    #[error("address domain name must be UTF-8 encoding")]
    AddressDomainInvalidEncoding,
    #[error("address type {0:#x} not supported")]
    AddressTypeNotSupported(u8),
}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::Io(err) => err,
            _ => todo!(),
        }
    }
}
