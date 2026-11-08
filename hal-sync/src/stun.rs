use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;

pub const STUN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
pub const STUN_HEADER_SIZE: usize = 20;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub const STUN_DEFAULT_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

#[derive(Debug, Clone)]
pub struct StunConfig {
    pub servers: Vec<String>,
    pub timeout: Duration,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: STUN_DEFAULT_SERVERS
                .iter()
                .map(|server| server.to_string())
                .collect(),
            timeout: STUN_DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicEndpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub server: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    Timeout,
    NetworkError(String),
    InvalidResponse,
    NoServers,
    NoResponse,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(formatter, "STUN request timed out"),
            Self::NetworkError(error) => write!(formatter, "STUN network error: {error}"),
            Self::InvalidResponse => write!(formatter, "invalid STUN response"),
            Self::NoServers => write!(formatter, "no STUN servers configured"),
            Self::NoResponse => write!(formatter, "STUN servers returned no response"),
        }
    }
}

impl std::error::Error for StunError {}

pub struct StunClient {
    config: StunConfig,
}

impl StunClient {
    pub fn new(config: StunConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(StunConfig::default())
    }

    pub async fn discover(&self) -> Result<PublicEndpoint, StunError> {
        if self.config.servers.is_empty() {
            return Err(StunError::NoServers);
        }

        let mut last_error = StunError::NoResponse;
        for server in &self.config.servers {
            match resolve_server(server).await {
                Ok(server_addr) => match self.discover_server(server_addr).await {
                    Ok(endpoint) => return Ok(endpoint),
                    Err(error) => last_error = error,
                },
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub async fn discover_multi(&self) -> Result<Vec<PublicEndpoint>, StunError> {
        if self.config.servers.is_empty() {
            return Err(StunError::NoServers);
        }

        let mut endpoints = Vec::new();
        let mut last_error = StunError::NoResponse;
        for server in &self.config.servers {
            match resolve_server(server).await {
                Ok(server_addr) => match self.discover_server(server_addr).await {
                    Ok(endpoint) => endpoints.push(endpoint),
                    Err(error) => last_error = error,
                },
                Err(error) => last_error = error,
            }
        }

        if endpoints.is_empty() {
            Err(last_error)
        } else {
            Ok(endpoints)
        }
    }

    pub async fn discover_on_socket(
        &self,
        socket: &UdpSocket,
    ) -> Result<PublicEndpoint, StunError> {
        if self.config.servers.is_empty() {
            return Err(StunError::NoServers);
        }

        let mut last_error = StunError::NoResponse;
        for server in &self.config.servers {
            match resolve_server(server).await {
                Ok(server_addr) => {
                    match self.discover_server_on_socket(socket, server_addr).await {
                        Ok(endpoint) => return Ok(endpoint),
                        Err(error) => last_error = error,
                    }
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub async fn discover_multi_on_socket(
        &self,
        socket: &UdpSocket,
    ) -> Result<Vec<PublicEndpoint>, StunError> {
        if self.config.servers.is_empty() {
            return Err(StunError::NoServers);
        }

        let mut endpoints = Vec::new();
        let mut last_error = StunError::NoResponse;
        for server in &self.config.servers {
            match resolve_server(server).await {
                Ok(server_addr) => {
                    match self.discover_server_on_socket(socket, server_addr).await {
                        Ok(endpoint) => endpoints.push(endpoint),
                        Err(error) => last_error = error,
                    }
                }
                Err(error) => last_error = error,
            }
        }
        if endpoints.is_empty() {
            Err(last_error)
        } else {
            Ok(endpoints)
        }
    }

    async fn discover_server(&self, server: SocketAddr) -> Result<PublicEndpoint, StunError> {
        let socket = UdpSocket::bind("[::]:0")
            .await
            .map_err(|error| StunError::NetworkError(error.to_string()))?;
        match self.discover_server_on_socket(&socket, server).await {
            Ok(endpoint) => Ok(endpoint),
            Err(error) if server.is_ipv4() => {
                let fallback = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|bind_error| StunError::NetworkError(bind_error.to_string()))?;
                self.discover_server_on_socket(&fallback, server)
                    .await
                    .map_err(|fallback_error| {
                        StunError::NetworkError(format!(
                            "dual-stack socket failed ({error}); IPv4 fallback failed ({fallback_error})"
                        ))
                    })
            }
            Err(error) => Err(error),
        }
    }

    async fn discover_server_on_socket(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
    ) -> Result<PublicEndpoint, StunError> {
        let request = build_binding_request();
        socket
            .send_to(&request, server)
            .await
            .map_err(|error| StunError::NetworkError(error.to_string()))?;

        let mut response = [0u8; 2048];
        let (received, source) = timeout(self.config.timeout, socket.recv_from(&mut response))
            .await
            .map_err(|_| StunError::Timeout)?
            .map_err(|error| StunError::NetworkError(error.to_string()))?;

        if source != server || received < STUN_HEADER_SIZE || response[8..20] != request[8..20] {
            return Err(StunError::InvalidResponse);
        }
        let endpoint = parse_binding_response(&response[..received], server)?;
        if endpoint.ip.is_unspecified() || endpoint.port == 0 {
            return Err(StunError::InvalidResponse);
        }
        Ok(endpoint)
    }
}

async fn resolve_server(server: &str) -> Result<SocketAddr, StunError> {
    lookup_host(server)
        .await
        .map_err(|error| StunError::NetworkError(error.to_string()))?
        .next()
        .ok_or_else(|| StunError::NetworkError("STUN server has no addresses".to_string()))
}

fn build_binding_request() -> [u8; STUN_HEADER_SIZE] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut transaction_id = [0u8; 12];
    let first = (time as u64).to_be_bytes();
    let second = (counter ^ (time as u64)).to_be_bytes();
    transaction_id[..8].copy_from_slice(&first);
    transaction_id[4..12].copy_from_slice(&second);

    let mut request = [0u8; STUN_HEADER_SIZE];
    request[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

fn parse_binding_response(data: &[u8], server: SocketAddr) -> Result<PublicEndpoint, StunError> {
    if data.len() < STUN_HEADER_SIZE
        || u16::from_be_bytes([data[0], data[1]]) != STUN_BINDING_RESPONSE
        || u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != STUN_MAGIC_COOKIE
    {
        return Err(StunError::InvalidResponse);
    }

    let message_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if message_length % 4 != 0 || STUN_HEADER_SIZE + message_length > data.len() {
        return Err(StunError::InvalidResponse);
    }

    let transaction_id = &data[8..20];
    let mut offset = STUN_HEADER_SIZE;
    let end = STUN_HEADER_SIZE + message_length;
    let mut mapped = None;
    while offset + 4 <= end {
        let attribute_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attribute_length =
            usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
        let value_start = offset + 4;
        let value_end = value_start.saturating_add(attribute_length);
        if value_end > end {
            return Err(StunError::InvalidResponse);
        }
        let value = &data[value_start..value_end];
        if attribute_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            mapped = decode_xor_mapped_address_with_transaction(value, transaction_id);
            if mapped.is_some() {
                break;
            }
        } else if attribute_type == STUN_ATTR_MAPPED_ADDRESS && mapped.is_none() {
            mapped = decode_mapped_address(value);
        }
        offset = value_start + ((attribute_length + 3) & !3);
    }

    mapped
        .map(|(ip, port)| PublicEndpoint { ip, port, server })
        .ok_or(StunError::NoResponse)
}

fn decode_xor_mapped_address(data: &[u8]) -> Option<(IpAddr, u16)> {
    decode_xor_mapped_address_with_transaction(data, &[0u8; 12])
}

fn decode_xor_mapped_address_with_transaction(
    data: &[u8],
    transaction_id: &[u8],
) -> Option<(IpAddr, u16)> {
    if data.len() < 8 || data[0] != 0 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    match family {
        0x01 => {
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let mut address = [0u8; 4];
            for index in 0..4 {
                address[index] = data[4 + index] ^ cookie[index];
            }
            Some((IpAddr::V4(Ipv4Addr::from(address)), port))
        }
        0x02 if data.len() >= 20 && transaction_id.len() >= 12 => {
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let mut address = [0u8; 16];
            for index in 0..4 {
                address[index] = data[4 + index] ^ cookie[index];
            }
            for index in 0..12 {
                address[index + 4] = data[index + 8] ^ transaction_id[index];
            }
            Some((IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => None,
    }
}

fn decode_mapped_address(data: &[u8]) -> Option<(IpAddr, u16)> {
    if data.len() < 8 || data[0] != 0 {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    match data[1] {
        0x01 => Some((
            IpAddr::V4(Ipv4Addr::new(data[4], data[5], data[6], data[7])),
            port,
        )),
        0x02 if data.len() >= 20 => {
            let mut address = [0u8; 16];
            address.copy_from_slice(&data[4..20]);
            Some((IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_response_with_xor_mapped(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let transaction_id = [0u8; 12];
        let mut response = vec![0u8; STUN_HEADER_SIZE + 12];
        response[..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[24] = 0;
        response[25] = 1;
        response[26..28].copy_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let address = u32::from(ip) ^ STUN_MAGIC_COOKIE;
        response[28..32].copy_from_slice(&address.to_be_bytes());
        response
    }

    fn build_response_with_mapped(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut response = vec![0u8; STUN_HEADER_SIZE + 12];
        response[..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[20..22].copy_from_slice(&STUN_ATTR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[24] = 0;
        response[25] = 1;
        response[26..28].copy_from_slice(&port.to_be_bytes());
        response[28..32].copy_from_slice(&u32::from(ip).to_be_bytes());
        response
    }

    #[test]
    fn build_binding_request_correct_size() {
        let request = build_binding_request();
        assert_eq!(request.len(), 20);
        assert_eq!(&request[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
    }

    #[test]
    fn parse_binding_response_xor_mapped() {
        let response = build_response_with_xor_mapped(Ipv4Addr::new(203, 0, 113, 7), 4242);
        let endpoint =
            parse_binding_response(&response, "127.0.0.1:3478".parse().unwrap()).unwrap();
        assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(endpoint.port, 4242);
    }

    #[test]
    fn parse_binding_response_mapped() {
        let response = build_response_with_mapped(Ipv4Addr::new(198, 51, 100, 9), 5353);
        let endpoint =
            parse_binding_response(&response, "127.0.0.1:3478".parse().unwrap()).unwrap();
        assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(endpoint.port, 5353);
    }

    #[test]
    fn parse_invalid_response_rejected() {
        let mut response = build_response_with_mapped(Ipv4Addr::LOCALHOST, 1234);
        response[0] = 0;
        assert_eq!(
            parse_binding_response(&response, "127.0.0.1:3478".parse().unwrap()),
            Err(StunError::InvalidResponse)
        );
    }

    #[test]
    fn decode_xor_mapped_address_ipv4() {
        let response = build_response_with_xor_mapped(Ipv4Addr::new(192, 0, 2, 1), 5000);
        assert_eq!(
            decode_xor_mapped_address(&response[24..32]),
            Some((IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5000))
        );
    }

    #[test]
    fn decode_xor_mapped_address_ipv6() {
        let ip = Ipv6Addr::LOCALHOST;
        let mut attribute = vec![0, 2, 0, 0];
        attribute.extend_from_slice(&[0u8; 16]);
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let address = ip.octets();
        for index in 0..4 {
            attribute[4 + index] = address[index] ^ cookie[index];
        }
        for index in 4..16 {
            attribute[4 + index] = address[index];
        }
        assert_eq!(
            decode_xor_mapped_address(&attribute),
            Some((IpAddr::V6(ip), 0 ^ (STUN_MAGIC_COOKIE >> 16) as u16))
        );
    }
}
