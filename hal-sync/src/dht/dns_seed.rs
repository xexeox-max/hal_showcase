use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::time::timeout;

pub const DNS_SEED_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DNS_SEED_DEFAULT_HOSTS: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
];

#[derive(Debug, Clone)]
pub struct DnsSeedConfig {
    pub hosts: Vec<String>,
    pub timeout: Duration,
}

impl Default for DnsSeedConfig {
    fn default() -> Self {
        Self {
            hosts: DNS_SEED_DEFAULT_HOSTS
                .iter()
                .map(|host| host.to_string())
                .collect(),
            timeout: DNS_SEED_DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsSeedError {
    NoHosts,
    Timeout,
    ResolutionFailed(String),
    NoAddresses,
}

impl fmt::Display for DnsSeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHosts => write!(formatter, "no DNS seed hosts configured"),
            Self::Timeout => write!(formatter, "DNS seed resolution timed out"),
            Self::ResolutionFailed(error) => {
                write!(formatter, "DNS seed resolution failed: {error}")
            }
            Self::NoAddresses => write!(formatter, "DNS seed hosts returned no addresses"),
        }
    }
}

impl std::error::Error for DnsSeedError {}

pub struct DnsSeedResolver {
    config: DnsSeedConfig,
}

impl DnsSeedResolver {
    pub fn new(config: DnsSeedConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(DnsSeedConfig::default())
    }

    pub fn config(&self) -> &DnsSeedConfig {
        &self.config
    }

    pub async fn resolve(&self) -> Result<Vec<SocketAddr>, DnsSeedError> {
        if self.config.hosts.is_empty() {
            return Err(DnsSeedError::NoHosts);
        }

        let mut addresses = Vec::new();
        let mut failures = Vec::new();
        for host in &self.config.hosts {
            match self.resolve_host(host).await {
                Ok(resolved) => {
                    for address in resolved {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Err(error) => {
                    log::warn!(target: "HAL_DHT", "DNS bootstrap host {host} failed: {error}");
                    failures.push(format!("{host}: {error}"));
                }
            }
        }

        if addresses.is_empty() {
            if failures.is_empty() {
                Err(DnsSeedError::NoAddresses)
            } else {
                Err(DnsSeedError::ResolutionFailed(failures.join("; ")))
            }
        } else {
            Ok(addresses)
        }
    }

    pub async fn resolve_host(&self, host: &str) -> Result<Vec<SocketAddr>, DnsSeedError> {
        let resolved = timeout(self.config.timeout, lookup_host(host))
            .await
            .map_err(|_| DnsSeedError::Timeout)?
            .map_err(|error| DnsSeedError::ResolutionFailed(error.to_string()))?;
        Ok(resolved.collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn config_default_values() {
        let config = DnsSeedConfig::default();
        assert_eq!(config.hosts.len(), DNS_SEED_DEFAULT_HOSTS.len());
        assert_eq!(config.timeout, DNS_SEED_DEFAULT_TIMEOUT);
    }

    #[test]
    fn config_custom_values() {
        let config = DnsSeedConfig {
            hosts: vec!["localhost:9000".to_string()],
            timeout: Duration::from_secs(1),
        };
        assert_eq!(config.hosts, vec!["localhost:9000"]);
        assert_eq!(config.timeout, Duration::from_secs(1));
    }

    #[test]
    fn new_creates_resolver() {
        let resolver = DnsSeedResolver::with_defaults();
        assert_eq!(resolver.config().hosts.len(), 3);
        assert_eq!(resolver.config().timeout, DNS_SEED_DEFAULT_TIMEOUT);
    }

    #[test]
    fn resolve_empty_hosts_fails() {
        let resolver = DnsSeedResolver::new(DnsSeedConfig {
            hosts: Vec::new(),
            timeout: DNS_SEED_DEFAULT_TIMEOUT,
        });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(resolver.resolve());
        assert_eq!(result, Err(DnsSeedError::NoHosts));
    }

    #[test]
    fn resolve_localhost_works() {
        let resolver = DnsSeedResolver::new(DnsSeedConfig {
            hosts: vec!["localhost:9000".to_string()],
            timeout: Duration::from_secs(1),
        });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(resolver.resolve()).unwrap();
        assert!(result.iter().any(|address| {
            address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && address.port() == 9000
        }));
    }

    #[test]
    fn resolve_continues_after_a_seed_dns_failure() {
        let resolver = DnsSeedResolver::new(DnsSeedConfig {
            hosts: vec![
                "nonexistent.invalid:6881".to_string(),
                "127.0.0.1:6881".to_string(),
            ],
            timeout: Duration::from_secs(2),
        });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(resolver.resolve()).unwrap();

        assert!(result.iter().any(|address| {
            address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && address.port() == 6881
        }));
    }
}
