use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Instant};

use crate::dht::endpoint_lookup::EndpointLookup;
use crate::dht::NodeId;
use crate::signaling::{CoordinationChannel, SignalingStrategy};
use crate::stun::PublicEndpoint;

pub const PUNCH_DEFAULT_MAX_ATTEMPTS: u32 = 50;
pub const PUNCH_DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
pub const PUNCH_DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
pub const PUNCH_MAGIC: &[u8; 8] = b"HAL-PNCH";

#[derive(Debug, Clone)]
pub struct PunchConfig {
    pub max_attempts: u32,
    pub retry_interval: Duration,
    pub total_timeout: Duration,
    pub magic: [u8; 8],
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            max_attempts: PUNCH_DEFAULT_MAX_ATTEMPTS,
            retry_interval: PUNCH_DEFAULT_RETRY_INTERVAL,
            total_timeout: PUNCH_DEFAULT_TOTAL_TIMEOUT,
            magic: *PUNCH_MAGIC,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PunchCoordination {
    /// Прямая координация (уже есть канал).
    Direct {
        /// Публичный endpoint удалённой стороны.
        remote: PublicEndpoint,
    },
    /// Через DHT (публикуем/читаем endpoint).
    ViaDht {
        /// Remote node id (для поиска в DHT).
        remote_id: NodeId,
    },
}

#[derive(Debug)]
pub enum PunchOutcome {
    /// Успех — соединение установлено.
    Punched {
        socket: UdpSocket,
        remote: SocketAddr,
    },
    /// Failed — не удалось.
    Failed { error: PunchError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchError {
    BindFailed(String),
    NoRemote,
    Timeout,
    NetworkError(String),
    InvalidMagic,
}

impl fmt::Display for PunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindFailed(error) => write!(formatter, "UDP bind failed: {error}"),
            Self::NoRemote => write!(formatter, "no remote endpoint available"),
            Self::Timeout => write!(formatter, "UDP hole punching timed out"),
            Self::NetworkError(error) => write!(formatter, "UDP network error: {error}"),
            Self::InvalidMagic => write!(formatter, "invalid hole punch magic"),
        }
    }
}

impl std::error::Error for PunchError {}

#[derive(Debug, Clone)]
pub struct HolePuncher {
    config: PunchConfig,
}

impl HolePuncher {
    pub fn new(config: PunchConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(PunchConfig::default())
    }

    pub fn config(&self) -> &PunchConfig {
        &self.config
    }
}

pub async fn punch_hole(
    puncher: &HolePuncher,
    local_bind: SocketAddr,
    coordination: PunchCoordination,
    lookup: Option<Arc<dyn EndpointLookup>>,
) -> PunchOutcome {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let endpoints = match coordination {
        PunchCoordination::Direct { remote } => {
            vec![SocketAddr::new(remote.ip, remote.port)]
        }
        PunchCoordination::ViaDht { remote_id } => {
            let Some(lookup) = lookup else {
                return PunchOutcome::Failed {
                    error: PunchError::NoRemote,
                };
            };
            lookup.lookup(&remote_id, now).await
        }
    };

    if endpoints.is_empty() {
        return PunchOutcome::Failed {
            error: PunchError::NoRemote,
        };
    };

    let socket = match UdpSocket::bind(local_bind).await {
        Ok(socket) => socket,
        Err(error) => {
            return PunchOutcome::Failed {
                error: PunchError::BindFailed(error.to_string()),
            };
        }
    };

    let config = &puncher.config;
    for remote in endpoints {
        let result = timeout(config.total_timeout, async {
            let start = Instant::now();
            let mut buffer = [0u8; 1024];

            for _ in 0..config.max_attempts {
                if start.elapsed() >= config.total_timeout {
                    return Err(PunchError::Timeout);
                }

                if socket.send_to(&config.magic, remote).await.is_err() {
                    continue;
                }

                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        if let Ok((length, sender)) = received {
                            if sender == remote
                                && length >= config.magic.len()
                                && buffer[..config.magic.len()] == config.magic
                            {
                                return Ok(());
                            }
                        }
                    }
                    _ = sleep(config.retry_interval) => {}
                }
            }

            Err(PunchError::Timeout)
        })
        .await;

        if matches!(result, Ok(Ok(()))) {
            return PunchOutcome::Punched { socket, remote };
        }
    }

    PunchOutcome::Failed {
        error: PunchError::NoRemote,
    }
}

/// Punch с выбором канала через SignalingStrategy.
///
/// Стратегия выбирает CoordinationChannel по seed.
/// Пока поддерживается только Dht -> ViaDht.
/// Остальные каналы завершаются NoRemote до реализации адаптеров.
pub async fn punch_hole_with_strategy(
    puncher: &HolePuncher,
    local_bind: SocketAddr,
    target_id: NodeId,
    strategy: &SignalingStrategy,
    lookup: Option<Arc<dyn EndpointLookup>>,
    seed: u64,
) -> PunchOutcome {
    let Some(channel) = strategy.pick_channel(seed) else {
        return PunchOutcome::Failed {
            error: PunchError::NoRemote,
        };
    };

    let coordination = match channel {
        CoordinationChannel::Dht => PunchCoordination::ViaDht {
            remote_id: target_id,
        },
        // TODO(N4d.2b.2): ExistingTcp / Group / Referral / Relay / Invite.
        _ => {
            return PunchOutcome::Failed {
                error: PunchError::NoRemote,
            };
        }
    };

    punch_hole(puncher, local_bind, coordination, lookup).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct EmptyLookup;

    #[async_trait]
    impl EndpointLookup for EmptyLookup {
        async fn lookup(&self, _node_id: &NodeId, _now: u64) -> Vec<SocketAddr> {
            Vec::new()
        }
    }

    struct SingleLookup;

    #[async_trait]
    impl EndpointLookup for SingleLookup {
        async fn lookup(&self, _node_id: &NodeId, _now: u64) -> Vec<SocketAddr> {
            vec!["127.0.0.1:9999".parse().unwrap()]
        }
    }

    fn endpoint() -> PublicEndpoint {
        PublicEndpoint {
            ip: "127.0.0.1".parse().unwrap(),
            port: 9000,
            server: "127.0.0.1:3478".parse().unwrap(),
        }
    }

    #[test]
    fn config_default_values() {
        let config = PunchConfig::default();
        assert_eq!(config.max_attempts, PUNCH_DEFAULT_MAX_ATTEMPTS);
        assert_eq!(config.retry_interval, PUNCH_DEFAULT_RETRY_INTERVAL);
        assert_eq!(config.total_timeout, PUNCH_DEFAULT_TOTAL_TIMEOUT);
        assert_eq!(config.magic, *PUNCH_MAGIC);
    }

    #[test]
    fn new_creates_puncher() {
        let puncher = HolePuncher::with_defaults();
        assert_eq!(puncher.config().magic, *PUNCH_MAGIC);
    }

    #[test]
    fn punch_coordination_direct_constructible() {
        let coordination = PunchCoordination::Direct { remote: endpoint() };
        assert!(matches!(coordination, PunchCoordination::Direct { .. }));
    }

    #[test]
    fn punch_coordination_via_dht_constructible() {
        let coordination = PunchCoordination::ViaDht {
            remote_id: NodeId::from_bytes([7; 32]),
        };
        assert!(matches!(coordination, PunchCoordination::ViaDht { .. }));
    }

    #[test]
    fn punch_outcome_failed_constructible() {
        let outcome = PunchOutcome::Failed {
            error: PunchError::NoRemote,
        };
        assert!(matches!(outcome, PunchOutcome::Failed { .. }));
    }

    #[test]
    fn punch_error_display() {
        assert_eq!(
            PunchError::NoRemote.to_string(),
            "no remote endpoint available"
        );
        assert!(PunchError::Timeout.to_string().contains("timed out"));
    }

    #[test]
    fn punch_hole_direct_without_lookup() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(async {
            let puncher = HolePuncher::new(PunchConfig {
                max_attempts: 1,
                retry_interval: Duration::from_millis(10),
                total_timeout: Duration::from_millis(50),
                magic: *PUNCH_MAGIC,
            });
            tokio::time::timeout(
                Duration::from_millis(500),
                punch_hole(
                    &puncher,
                    "127.0.0.1:0".parse().unwrap(),
                    PunchCoordination::Direct { remote: endpoint() },
                    None,
                ),
            )
            .await
            .expect("hole punch timeout")
        });
        assert!(matches!(
            outcome,
            PunchOutcome::Punched { .. } | PunchOutcome::Failed { .. }
        ));
    }

    #[test]
    fn punch_hole_via_dht_without_lookup_fails() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(punch_hole(
            &HolePuncher::with_defaults(),
            "127.0.0.1:0".parse().unwrap(),
            PunchCoordination::ViaDht {
                remote_id: NodeId::from_bytes([8; 32]),
            },
            None,
        ));
        assert!(matches!(
            outcome,
            PunchOutcome::Failed {
                error: PunchError::NoRemote
            }
        ));
    }

    #[test]
    fn punch_hole_via_dht_empty_lookup_fails() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(punch_hole(
            &HolePuncher::with_defaults(),
            "127.0.0.1:0".parse().unwrap(),
            PunchCoordination::ViaDht {
                remote_id: NodeId::from_bytes([9; 32]),
            },
            Some(Arc::new(EmptyLookup)),
        ));
        assert!(matches!(
            outcome,
            PunchOutcome::Failed {
                error: PunchError::NoRemote
            }
        ));
    }

    #[test]
    fn punch_hole_via_dht_with_endpoint_attempts() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(async {
            let puncher = HolePuncher::new(PunchConfig {
                max_attempts: 1,
                retry_interval: Duration::from_millis(10),
                total_timeout: Duration::from_millis(50),
                magic: *PUNCH_MAGIC,
            });
            tokio::time::timeout(
                Duration::from_millis(500),
                punch_hole(
                    &puncher,
                    "127.0.0.1:0".parse().unwrap(),
                    PunchCoordination::ViaDht {
                        remote_id: NodeId::from_bytes([10; 32]),
                    },
                    Some(Arc::new(SingleLookup)),
                ),
            )
            .await
            .expect("hole punch timeout")
        });
        assert!(matches!(
            outcome,
            PunchOutcome::Punched { .. } | PunchOutcome::Failed { .. }
        ));
    }

    #[test]
    fn strategy_dht_returns_via_dht() {
        let strategy = SignalingStrategy::only_dht();
        let channel = strategy.pick_channel(0).expect("DHT channel");
        assert!(matches!(channel, CoordinationChannel::Dht));
    }

    #[test]
    fn strategy_unsupported_channel_fails() {
        let runtime = tokio::runtime::Runtime::new().expect("create runtime");
        let outcome = runtime.block_on(punch_hole_with_strategy(
            &HolePuncher::with_defaults(),
            "127.0.0.1:0".parse().expect("local bind address"),
            NodeId::from_bytes([11; 32]),
            &SignalingStrategy {
                channels: vec![(CoordinationChannel::ExistingTcp, 1)],
                formats: vec![(crate::signaling::SignalingFormat::Explicit, 1)],
                randomize: false,
                rotate_on_retry: false,
            },
            None,
            0,
        ));
        assert!(matches!(
            outcome,
            PunchOutcome::Failed {
                error: PunchError::NoRemote
            }
        ));
    }

    #[test]
    fn strategy_no_channel_fails() {
        let runtime = tokio::runtime::Runtime::new().expect("create runtime");
        let outcome = runtime.block_on(punch_hole_with_strategy(
            &HolePuncher::with_defaults(),
            "127.0.0.1:0".parse().expect("local bind address"),
            NodeId::from_bytes([12; 32]),
            &SignalingStrategy {
                channels: Vec::new(),
                formats: vec![(crate::signaling::SignalingFormat::Explicit, 1)],
                randomize: false,
                rotate_on_retry: false,
            },
            None,
            0,
        ));
        assert!(matches!(
            outcome,
            PunchOutcome::Failed {
                error: PunchError::NoRemote
            }
        ));
    }
}
