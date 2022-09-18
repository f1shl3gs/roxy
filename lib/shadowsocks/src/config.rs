use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use crypto::encoding::base64;
use crypto::encoding::base64::urlsafe_decode_with_config;
use percent_encoding::percent_decode_str;
use tracing::error;
use url::Url;

use crate::addr::Address;
use crate::crypto::CipherKind;

/// Server Mode
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    TcpOnly = 0x01,
    UdpOnly = 0x02,
    TcpAndUdp = 0x03,
}

impl Mode {
    #[inline]
    fn enable_udp(self) -> bool {
        matches!(self, Mode::UdpOnly | Mode::TcpAndUdp)
    }

    #[inline]
    fn enable_tcp(self) -> bool {
        matches!(self, Mode::TcpOnly | Mode::TcpAndUdp)
    }
}

#[derive(Clone, Debug)]
pub struct ServerWeight {
    tcp_weight: f32,
    udp_weight: f32,
}

impl ServerWeight {
    pub fn new() -> Self {
        Self {
            tcp_weight: 1.0,
            udp_weight: 1.0,
        }
    }

    pub fn tcp_weight(&self) -> f32 {
        self.tcp_weight
    }

    pub fn udp_weight(&self) -> f32 {
        self.udp_weight
    }
}

impl Default for ServerWeight {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Server address
    addr: Address,
    /// Encryption password
    password: String,
    /// Encryption type method
    method: CipherKind,
    /// Encryption key
    enc_key: Box<[u8]>,
    /// Handshake timeout (connect)
    timeout: Option<Duration>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For client, assemble EIH headers
    identity_keys: Arc<Vec<Bytes>>,

    /// Remark (Profile Name), normally used as an identifier of this server
    remarks: Option<String>,
    /// ID (SIP008) is a random generated UUID
    id: Option<String>,

    /// Mode
    mode: Mode,

    /// Weight
    weight: ServerWeight,
}

/// Shadowsocks URL parsing Error
#[derive(Debug, Clone)]
pub enum UrlParseError {
    ParseError(url::ParseError),
    InvalidScheme,
    InvalidUserInfo,
    MissingHost,
    InvalidAuthInfo,
    InvalidServerAddr,
    InvalidQueryString,
}

impl From<url::ParseError> for UrlParseError {
    fn from(err: url::ParseError) -> Self {
        Self::ParseError(err)
    }
}

impl ServerConfig {
    pub fn new<A, P>(addr: A, password: P, method: CipherKind) -> ServerConfig
    where
        A: Into<Address>,
        P: Into<String>,
    {
        let (password, enc_key, identity_keys) = password_to_keys(method, password);

        ServerConfig {
            addr: addr.into(),
            password,
            method,
            enc_key,
            timeout: None,
            identity_keys: Arc::new(identity_keys),
            remarks: None,
            id: None,
            mode: Mode::TcpAndUdp,
            weight: Default::default(),
        }
    }

    /// Get server address
    pub fn addr(&self) -> &Address {
        &self.addr
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        self.enc_key.as_ref()
    }

    /// Get method
    pub fn kind(&self) -> CipherKind {
        self.method
    }

    pub fn remarks(&self) -> Option<&String> {
        self.remarks.as_ref()
    }

    pub fn weight(&self) -> &ServerWeight {
        &self.weight
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// Clone identity keys
    pub fn clone_identity_keys(&self) -> Arc<Vec<Bytes>> {
        self.identity_keys.clone()
    }

    pub fn tcp_enabled(&self) -> bool {
        self.mode.enable_tcp() && self.weight.tcp_weight > 0.0
    }

    pub fn udp_enabled(&self) -> bool {
        self.mode.enable_udp() && self.weight.udp_weight > 0.0
    }

    /// Parse from [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    ///
    /// Extended formats:
    ///
    /// 1. QRCode URL supported by shadowsocks-android, https://github.com/shadowsocks/shadowsocks-android/issues/51
    /// 2. Plain userinfo:password format supported by go2-shadowsocks2
    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        if parsed.scheme() != "ss" {
            return Err(UrlParseError::InvalidScheme);
        }

        let user_info = parsed.username();
        if user_info.is_empty() {
            // This maybe a QRCode URL, which is ss://BASE64-URL-ENCODE(pass:encrypt@hostname:port)

            let encoded = match parsed.host_str() {
                Some(e) => e,
                None => return Err(UrlParseError::MissingHost),
            };

            let mut decoded_body = match urlsafe_decode_with_config(
                encoded,
                base64::Config {
                    no_padding: true,
                    allow_trailing_non_zero_bits: false,
                },
            ) {
                Ok(b) => match String::from_utf8(b) {
                    Ok(b) => b,
                    Err(..) => return Err(UrlParseError::InvalidServerAddr),
                },
                Err(err) => {
                    error!(
                        "failed to parse legacy ss://ENCODED with Base64, err: {}",
                        err
                    );
                    return Err(UrlParseError::InvalidServerAddr);
                }
            };

            decoded_body.insert_str(0, "ss://");
            // Parse it like ss://method:password@host:port
            return ServerConfig::from_url(&decoded_body);
        }

        let (method, pwd) = match parsed.password() {
            Some(password) => {
                // Plain method:password without base64 encoded

                let m = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!(
                            "failed to parse percent-encoded method in userinfo, err: {}",
                            err
                        );
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                let p = match percent_encoding::percent_decode_str(password).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!(
                            "failed to parse percent-encoded password in userinfo, err: {}",
                            err
                        );
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                (m, p)
            }
            None => {
                let account = match urlsafe_decode_with_config(
                    user_info,
                    base64::Config {
                        no_padding: true,
                        allow_trailing_non_zero_bits: false,
                    },
                ) {
                    Ok(account) => match String::from_utf8(account) {
                        Ok(ac) => ac,
                        Err(..) => return Err(UrlParseError::InvalidAuthInfo),
                    },
                    Err(err) => {
                        error!("failed to parse UserInfo with Base64, err: {}", err);
                        return Err(UrlParseError::InvalidUserInfo);
                    }
                };

                let mut sp2 = account.splitn(2, ':');
                let (m, p) = match (sp2.next(), sp2.next()) {
                    (Some(m), Some(p)) => (m, p),
                    _ => return Err(UrlParseError::InvalidUserInfo),
                };

                (m.to_owned().into(), p.to_owned().into())
            }
        };

        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(8388);
        let addr = format!("{}:{}", host, port);

        let addr = match addr.parse::<Address>() {
            Ok(a) => a,
            Err(err) => {
                error!("failed to parse \"{}\" to ServerAddr, err: {:?}", addr, err);
                return Err(UrlParseError::InvalidServerAddr);
            }
        };

        let method = method.parse().expect("method");
        let mut svrconfig = ServerConfig::new(addr, pwd, method);

        if let Some(frag) = parsed.fragment() {
            let frag = percent_decode_str(frag).decode_utf8_lossy().to_string();
            svrconfig.remarks = Some(frag)
        }

        Ok(svrconfig)
    }
}

fn password_to_keys<P>(kind: CipherKind, password: P) -> (String, Box<[u8]>, Vec<Bytes>)
where
    P: Into<String>,
{
    let password = password.into();

    // TODO: aead 2022

    let mut enc_key = vec![0u8; kind.key_len()].into_boxed_slice();
    make_derived_key(kind, &password, &mut enc_key);

    (password, enc_key, vec![])
}

fn make_derived_key(kind: CipherKind, password: &str, enc_key: &mut [u8]) {
    if kind.is_aead2022() {
        match base64::decode(password) {
            Ok(v) => {
                if v.len() != enc_key.len() {
                    panic!(
                        "{} is expecting a {} bytes key, but password: {} ({} bytes after decode)",
                        kind,
                        enc_key.len(),
                        password,
                        v.len()
                    );
                }

                enc_key.copy_from_slice(&v);
            }

            Err(err) => {
                panic!(
                    "{} password {} is not base64 encoded, error: {}",
                    kind, password, err
                )
            }
        }
    } else {
        bytes_to_key(password.as_bytes(), enc_key)
    }
}

pub fn bytes_to_key(password: &[u8], key: &mut [u8]) {
    use crypto::hash::Md5;

    let key_len = key.len();
    let mut last_digest: Option<[u8; 16]> = None;

    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(key_len - offset, digest.len());
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += amt;
        last_digest = Some(digest);
    }
}

/// Check if method supports Extended Identity Header
///
/// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
#[inline]
pub fn method_support_eih(method: CipherKind) -> bool {
    matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    )
}

#[derive(Clone, Debug)]
pub struct ServerUser {
    name: String,
    key: Bytes,
    identity_hash: Bytes,
}
