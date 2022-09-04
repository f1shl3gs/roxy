use base64::DecodeError;
use hyper::StatusCode;
use shadowsocks::UrlParseError;

#[derive(Debug)]
pub enum Error {
    Http(hyper::Error),

    UnexpectedResponse(StatusCode),

    Decode(DecodeError),

    InvalidServerConfig(UrlParseError),
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Self::Http(err)
    }
}

impl From<StatusCode> for Error {
    fn from(status: StatusCode) -> Self {
        Self::UnexpectedResponse(status)
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<UrlParseError> for Error {
    fn from(err: UrlParseError) -> Self {
        Self::InvalidServerConfig(err)
    }
}
