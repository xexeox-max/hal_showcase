use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod frame {
    pub const DATA: u8 = 0x01;
    pub const WINDOW_UPDATE: u8 = 0x02;
    pub const OPEN: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const RST: u8 = 0x05;
    pub const PING: u8 = 0x06;
    pub const PONG: u8 = 0x07;
    pub const GOAWAY: u8 = 0x08;
    pub const HEADER: usize = 10;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    Sync,
    MediaSignal,
    Control,
    Priority,
    Dht,
}

impl StreamKind {
    fn encode(self) -> u8 {
        match self {
            Self::Sync => 1,
            Self::MediaSignal => 2,
            Self::Control => 3,
            Self::Priority => 4,
            Self::Dht => 5,
        }
    }

    fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sync),
            2 => Some(Self::MediaSignal),
            3 => Some(Self::Control),
            4 => Some(Self::Priority),
            5 => Some(Self::Dht),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MuxConfig {
    pub max_streams: usize,
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_frame_size: u32,
    pub keepalive_interval: Duration,
    pub pong_timeout: Duration,
    pub max_missed_pings: u8,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_streams: 32,
            stream_window: 32 * 1024,
            connection_window: 512 * 1024,
            max_frame_size: 32 * 1024,
            keepalive_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            max_missed_pings: 3,
        }
    }
}

pub(crate) enum DriverCommand {
    Data(u32, Bytes),
    Consumed(u32, u32),
    Close(u32),
    Reset(u32),
}

struct OpenRequest {
    kind: StreamKind,
    reply: oneshot::Sender<crate::mux_stream::MuxStream>,
}

struct StreamState {
    send_window: u32,
    recv_window: u32,
    read_tx: mpsc::UnboundedSender<Option<Bytes>>,
    pending: VecDeque<Bytes>,
    close_requested: bool,
    close_sent: bool,
}

pub struct Mux<S> {
    open_tx: mpsc::Sender<OpenRequest>,
    inbound_rx: mpsc::Receiver<crate::mux_stream::MuxStream>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    driver_handle: Option<JoinHandle<()>>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    marker: std::marker::PhantomData<S>,
}

#[derive(Clone, Debug)]
pub struct MuxSender {
    open_tx: mpsc::Sender<OpenRequest>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MuxSender {
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn open(&self, kind: StreamKind) -> Result<crate::mux_stream::MuxStream> {
        let (reply, result) = oneshot::channel();
        self.open_tx
            .send(OpenRequest { kind, reply })
            .await
            .map_err(|_| anyhow!("mux driver closed"))?;
        result.await.map_err(|_| anyhow!("mux open rejected"))
    }
}

impl<S> Mux<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(io: S, config: MuxConfig, mode: Mode) -> Self {
        Self::new_with_command_capacity(io, config, mode, 256)
    }

    #[cfg(test)]
    fn new_for_test(io: S, config: MuxConfig, mode: Mode, command_capacity: usize) -> Self {
        Self::new_with_command_capacity(io, config, mode, command_capacity)
    }

    fn new_with_command_capacity(
        io: S,
        config: MuxConfig,
        mode: Mode,
        command_capacity: usize,
    ) -> Self {
        let (open_tx, open_rx) = mpsc::channel(config.max_streams.max(1));
        let (inbound_tx, inbound_rx) = mpsc::channel(config.max_streams.max(1));
        let (command_tx, command_rx) = mpsc::channel(command_capacity.max(1));
        let command_tx = std::sync::Arc::new(command_tx);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let driver_handle = tokio::spawn(driver_loop(
            io,
            config,
            mode,
            open_rx,
            inbound_tx,
            command_rx,
            shutdown_rx,
            std::sync::Arc::clone(&command_tx),
            std::sync::Arc::clone(&alive),
        ));
        Self {
            open_tx,
            inbound_rx,
            shutdown_tx: Some(shutdown_tx),
            driver_handle: Some(driver_handle),
            alive,
            marker: std::marker::PhantomData,
        }
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn open(&self, kind: StreamKind) -> Result<crate::mux_stream::MuxStream> {
        self.sender().open(kind).await
    }

    pub fn sender(&self) -> MuxSender {
        MuxSender {
            open_tx: self.open_tx.clone(),
            alive: std::sync::Arc::clone(&self.alive),
        }
    }

    pub async fn accept(&mut self) -> Option<crate::mux_stream::MuxStream> {
        self.inbound_rx.recv().await
    }

    pub async fn close(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(());
        }
        if let Some(handle) = self.driver_handle.take() {
            handle
                .await
                .map_err(|error| anyhow!("mux driver: {error}"))?;
        }
        Ok(())
    }
}

async fn driver_loop<S>(
    mut io: S,
    config: MuxConfig,
    mode: Mode,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    inbound_tx: mpsc::Sender<crate::mux_stream::MuxStream>,
    mut command_rx: mpsc::Receiver<DriverCommand>,
    mut shutdown_rx: oneshot::Receiver<()>,
    command_tx: std::sync::Arc<mpsc::Sender<DriverCommand>>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    let mut read_buf = BytesMut::with_capacity(frame::HEADER + config.max_frame_size as usize);
    let mut write_queue: VecDeque<Bytes> = VecDeque::new();
    let mut next_id: u32 = match mode {
        Mode::Client => 1,
        Mode::Server => 2,
    };
    let mut connection_send_window = config.connection_window;
    let mut awaiting_pong = false;
    let mut missed_pings = 0u8;
    let mut pong_deadline = None;
    let mut shutting_down = false;
    let mut close_reason = None;
    let mut keepalive = (config.keepalive_interval > Duration::ZERO)
        .then(|| tokio::time::interval(config.keepalive_interval));

    loop {
        if let Some(bytes) = write_queue.pop_front() {
            if let Err(error) = io.write_all(&bytes).await {
                close_reason = Some(format!("write failed: {error}"));
                break;
            }
            continue;
        }

        if shutting_down {
            let _ = io.write_all(&encode_frame(frame::GOAWAY, 0, &[])).await;
            let _ = io.flush().await;
            break;
        }

        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                while let Ok(command) = command_rx.try_recv() {
                    handle_command(
                        command,
                        &config,
                        &mut streams,
                        &mut write_queue,
                        &mut connection_send_window,
                    );
                }
                shutting_down = true;
            }
            _ = async {
                if let Some(interval) = &mut keepalive {
                    interval.tick().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if !shutting_down && keepalive.is_some() => {
                if !awaiting_pong {
                    write_queue.push_back(encode_frame(frame::PING, 0, &[]));
                    awaiting_pong = true;
                    pong_deadline = Some(tokio::time::Instant::now() + config.pong_timeout);
                }
            }
            _ = async {
                if let Some(deadline) = pong_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if !shutting_down && awaiting_pong => {
                missed_pings = missed_pings.saturating_add(1);
                log::warn!(
                    "mux keepalive missed pong ({missed_pings}/{}); connection may be unhealthy",
                    config.max_missed_pings
                );
                awaiting_pong = false;
                pong_deadline = None;
                if missed_pings >= config.max_missed_pings {
                    close_reason = Some("keepalive pong timeout".to_string());
                    shutting_down = true;
                }
            }
            result = io.read_buf(&mut read_buf), if read_buf.len() < frame::HEADER + config.max_frame_size as usize => {
                match result {
                    Ok(0) => {
                        close_reason = Some("peer closed connection".to_string());
                        break;
                    }
                    Ok(_) => {
                        loop {
                            let Some((kind, id, payload)) = parse_frame(&mut read_buf, config.max_frame_size) else { break };
                            if let Err(error) = handle_frame(
                                kind,
                                id,
                                payload,
                                &config,
                                &mut streams,
                                &mut write_queue,
                                &mut connection_send_window,
                                &inbound_tx,
                                &command_tx,
                                &mut awaiting_pong,
                                &mut missed_pings,
                                &mut pong_deadline,
                            ).await {
                                close_reason = Some(format!("invalid mux frame: {error}"));
                                shutting_down = true;
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        close_reason = Some(format!("read failed: {error}"));
                        break;
                    }
                }
            }
            request = open_rx.recv() => {
                let Some(request) = request else { break };
                if streams.len() >= config.max_streams {
                    drop(request.reply);
                    continue;
                }
                let id = next_id;
                next_id = next_id.saturating_add(2);
                let (read_tx, read_rx) = mpsc::unbounded_channel();
                let stream = crate::mux_stream::MuxStream::new(id, request.kind, read_rx, command_tx.clone());
                streams.insert(id, StreamState {
                    send_window: config.stream_window,
                    recv_window: config.stream_window,
                    read_tx,
                    pending: VecDeque::new(),
                    close_requested: false,
                    close_sent: false,
                });
                let _ = request.reply.send(stream);
                write_queue.push_back(encode_frame(frame::OPEN, id, &[request.kind.encode()]));
            }
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                handle_command(command, &config, &mut streams, &mut write_queue, &mut connection_send_window);
            }
        }
    }

    for (_, state) in streams {
        let _ = state.read_tx.send(None);
    }
    alive.store(false, std::sync::atomic::Ordering::Release);
    if let Some(reason) = close_reason {
        log::warn!("mux driver closed: {reason}");
    }
}

async fn handle_frame(
    kind: u8,
    id: u32,
    payload: Bytes,
    config: &MuxConfig,
    streams: &mut HashMap<u32, StreamState>,
    write_queue: &mut VecDeque<Bytes>,
    connection_send_window: &mut u32,
    inbound_tx: &mpsc::Sender<crate::mux_stream::MuxStream>,
    command_tx: &std::sync::Arc<mpsc::Sender<DriverCommand>>,
    awaiting_pong: &mut bool,
    missed_pings: &mut u8,
    pong_deadline: &mut Option<tokio::time::Instant>,
) -> Result<()> {
    match kind {
        frame::OPEN => {
            let Some(stream_kind) = payload.first().and_then(|value| StreamKind::decode(*value))
            else {
                return Err(anyhow!("invalid stream kind"));
            };
            if streams.len() >= config.max_streams || streams.contains_key(&id) {
                write_queue.push_back(encode_frame(frame::RST, id, &[]));
                return Ok(());
            }
            let (read_tx, read_rx) = mpsc::unbounded_channel();
            let stream =
                crate::mux_stream::MuxStream::new(id, stream_kind, read_rx, command_tx.clone());
            streams.insert(
                id,
                StreamState {
                    send_window: config.stream_window,
                    recv_window: config.stream_window,
                    read_tx,
                    pending: VecDeque::new(),
                    close_requested: false,
                    close_sent: false,
                },
            );
            if inbound_tx.try_send(stream).is_err() {
                write_queue.push_back(encode_frame(frame::RST, id, &[]));
            }
        }
        frame::DATA => {
            let Some(state) = streams.get_mut(&id) else {
                write_queue.push_back(encode_frame(frame::RST, id, &[]));
                return Ok(());
            };
            if payload.len() as u32 > state.recv_window
                || payload.len() as u32 > config.connection_window
            {
                write_queue.push_back(encode_frame(frame::RST, id, &[]));
                return Ok(());
            }
            state.recv_window -= payload.len() as u32;
            let _ = state.read_tx.send(Some(payload));
        }
        frame::WINDOW_UPDATE => {
            if payload.len() != 4 {
                return Err(anyhow!("invalid window update"));
            }
            let amount =
                u32::from_be_bytes(payload[..4].try_into().map_err(|_| anyhow!("window"))?);
            if id == 0 {
                *connection_send_window = connection_send_window.saturating_add(amount);
            } else if let Some(state) = streams.get_mut(&id) {
                state.send_window = state.send_window.saturating_add(amount);
                flush_pending(
                    id,
                    state,
                    write_queue,
                    connection_send_window,
                    config.max_frame_size,
                );
            }
        }
        frame::CLOSE | frame::RST => {
            if let Some(state) = streams.remove(&id) {
                let _ = state.read_tx.send(None);
                if kind == frame::CLOSE {
                    write_queue.push_back(encode_frame(frame::CLOSE, id, &[]));
                }
            }
        }
        frame::PING => write_queue.push_back(encode_frame(frame::PONG, id, &[])),
        frame::PONG => {
            *awaiting_pong = false;
            *missed_pings = 0;
            *pong_deadline = None;
        }
        frame::GOAWAY => return Err(anyhow!("peer sent GOAWAY")),
        _ => return Err(anyhow!("unknown frame type")),
    }
    Ok(())
}

fn handle_command(
    command: DriverCommand,
    config: &MuxConfig,
    streams: &mut HashMap<u32, StreamState>,
    write_queue: &mut VecDeque<Bytes>,
    connection_send_window: &mut u32,
) {
    match command {
        DriverCommand::Data(id, data) => {
            if let Some(state) = streams.get_mut(&id) {
                state.pending.push_back(data);
                flush_pending(
                    id,
                    state,
                    write_queue,
                    connection_send_window,
                    config.max_frame_size,
                );
            }
        }
        DriverCommand::Consumed(id, amount) => {
            if let Some(state) = streams.get_mut(&id) {
                state.recv_window = state.recv_window.saturating_add(amount);
                write_queue.push_back(encode_frame(
                    frame::WINDOW_UPDATE,
                    id,
                    &amount.to_be_bytes(),
                ));
            }
            write_queue.push_back(encode_frame(frame::WINDOW_UPDATE, 0, &amount.to_be_bytes()));
        }
        DriverCommand::Close(id) => {
            if let Some(state) = streams.get_mut(&id) {
                state.close_requested = true;
                flush_pending(
                    id,
                    state,
                    write_queue,
                    connection_send_window,
                    config.max_frame_size,
                );
            }
        }
        DriverCommand::Reset(id) => {
            streams.remove(&id);
            write_queue.push_back(encode_frame(frame::RST, id, &[]));
        }
    }
}

fn flush_pending(
    id: u32,
    state: &mut StreamState,
    write_queue: &mut VecDeque<Bytes>,
    connection_send_window: &mut u32,
    max_frame_size: u32,
) {
    while let Some(data) = state.pending.front_mut() {
        if state.send_window == 0 || *connection_send_window == 0 {
            break;
        }
        let amount = data
            .len()
            .min(max_frame_size as usize)
            .min(state.send_window as usize)
            .min(*connection_send_window as usize);
        if amount == 0 {
            break;
        }
        let chunk = data.split_to(amount);
        state.send_window -= amount as u32;
        *connection_send_window -= amount as u32;
        write_queue.push_back(encode_frame(frame::DATA, id, &chunk));
        if data.is_empty() {
            state.pending.pop_front();
        }
    }
    if state.close_requested && state.pending.is_empty() && !state.close_sent {
        write_queue.push_back(encode_frame(frame::CLOSE, id, &[]));
        state.close_sent = true;
    }
}

fn encode_frame(kind: u8, id: u32, payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(frame::HEADER + payload.len());
    frame.extend_from_slice(&[1, kind]);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.freeze()
}

fn parse_frame(buffer: &mut BytesMut, max_frame_size: u32) -> Option<(u8, u32, Bytes)> {
    if buffer.len() < frame::HEADER {
        return None;
    }
    if buffer[0] != 1 {
        buffer.clear();
        return None;
    }
    let kind = buffer[1];
    let id = u32::from_be_bytes(buffer[2..6].try_into().ok()?);
    let length = u32::from_be_bytes(buffer[6..10].try_into().ok()?) as usize;
    if length > max_frame_size as usize {
        buffer.clear();
        return None;
    }
    if buffer.len() < frame::HEADER + length {
        return None;
    }
    buffer.advance(frame::HEADER);
    Some((kind, id, buffer.split_to(length).freeze()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn dht_stream_kind_roundtrips_with_distinct_code() {
        assert_eq!(StreamKind::Dht.encode(), 5);
        assert_eq!(StreamKind::decode(5), Some(StreamKind::Dht));
        assert_ne!(StreamKind::Dht.encode(), StreamKind::Sync.encode());
    }

    async fn pair() -> (Mux<tokio::io::DuplexStream>, Mux<tokio::io::DuplexStream>) {
        let (left, right) = tokio::io::duplex(128 * 1024);
        (
            Mux::new(left, MuxConfig::default(), Mode::Client),
            Mux::new(right, MuxConfig::default(), Mode::Server),
        )
    }

    #[tokio::test]
    async fn single_stream_roundtrip() {
        let (client, mut server) = pair().await;
        let stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        let mut stream = stream;
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        incoming.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn multiple_streams_concurrent() {
        let (client, mut server) = pair().await;
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(client.open(StreamKind::Sync).await.unwrap());
        }
        let mut incoming = Vec::new();
        for _ in 0..3 {
            incoming.push(server.accept().await.unwrap());
        }
        for (index, mut stream) in streams.into_iter().enumerate() {
            let payload = [b'a' + index as u8];
            stream.write_all(&payload).await.unwrap();
            let mut received = [0u8; 1];
            incoming[index].read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
        }
    }

    #[tokio::test]
    async fn flow_control_enforced() {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let config = MuxConfig {
            stream_window: 4,
            max_frame_size: 4,
            ..MuxConfig::default()
        };
        let client = Mux::new_for_test(left, config.clone(), Mode::Client, 4);
        let mut server = Mux::new_for_test(right, config, Mode::Server, 4);
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        let writer = tokio::spawn(async move {
            stream.write_all(b"12345678").await.unwrap();
        });
        let mut received = [0u8; 8];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            incoming.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();
        assert_eq!(&received, b"12345678");
    }

    #[tokio::test]
    async fn close_waits_for_pending_data() {
        let (client, mut server) = pair().await;
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        let payload = vec![0x5a; 5 * 1024 * 1024];

        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            incoming.read_to_end(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn backpressure_slow_reader() {
        let (left, _right) = tokio::io::duplex(1024);
        let client = Mux::new(
            left,
            MuxConfig {
                max_frame_size: 256,
                ..MuxConfig::default()
            },
            Mode::Client,
        );
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let payload = vec![7u8; 16 * 1024 * 1024];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(&payload),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn backpressure_resumes_after_drain() {
        let (command_tx, mut command_rx) = mpsc::channel(4);
        let (_read_tx, read_rx) = mpsc::unbounded_channel();
        let mut stream = crate::mux_stream::MuxStream::new(
            1,
            StreamKind::Sync,
            read_rx,
            std::sync::Arc::new(command_tx),
        );
        let payload = vec![7u8; 256 * 1024];
        let writer = tokio::spawn(async move { stream.write_all(&payload).await });
        for _ in 0..8 {
            tokio::time::timeout(std::time::Duration::from_secs(5), command_rx.recv())
                .await
                .unwrap()
                .expect("command");
        }
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn backpressure_bounded_memory() {
        let (left, _right) = tokio::io::duplex(1024);
        let client = Mux::new(
            left,
            MuxConfig {
                max_frame_size: 256,
                ..MuxConfig::default()
            },
            Mode::Client,
        );
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let payload = vec![7u8; 16 * 1024 * 1024];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(&payload),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn write_after_close_fails() {
        let (client, mut server) = pair().await;
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let _incoming = server.accept().await.unwrap();
        stream.shutdown().await.unwrap();
        let result = stream.write_all(b"after close").await;
        assert!(matches!(
            result,
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
    }

    #[tokio::test]
    async fn close_per_stream() {
        let (client, mut server) = pair().await;
        let stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        stream.close().await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), incoming.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn reset_per_stream() {
        let (client, mut server) = pair().await;
        let stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        stream.reset().await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), incoming.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn keepalive_ping_pong() {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let config = MuxConfig {
            keepalive_interval: std::time::Duration::from_millis(5),
            pong_timeout: std::time::Duration::from_millis(5),
            ..MuxConfig::default()
        };
        let client = Mux::new(left, config.clone(), Mode::Client);
        let mut server = Mux::new(right, config, Mode::Server);
        let mut stream = client.open(StreamKind::Sync).await.unwrap();
        let mut incoming = server.accept().await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut buf = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            incoming.read_exact(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn keepalive_timeout_closes() {
        let (left, mut right) = tokio::io::duplex(128 * 1024);
        let config = MuxConfig {
            keepalive_interval: std::time::Duration::from_millis(5),
            max_missed_pings: 2,
            ..MuxConfig::default()
        };
        let _client = Mux::new(left, config, Mode::Client);
        let mut bytes = [0u8; 10];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), right.read(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(read >= frame::HEADER);
        assert!(bytes[1] == frame::PING || bytes[1] == frame::GOAWAY);
    }

    #[tokio::test]
    async fn keepalive_uses_pong_timeout_before_closing() {
        let (left, _right) = tokio::io::duplex(128 * 1024);
        let client = Mux::new(
            left,
            MuxConfig {
                keepalive_interval: std::time::Duration::from_millis(5),
                pong_timeout: std::time::Duration::from_millis(10),
                max_missed_pings: 1,
                ..MuxConfig::default()
            },
            Mode::Client,
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while client.is_alive() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("mux should close after the configured pong timeout");
    }

    #[tokio::test]
    async fn goaway_shutdown() {
        let (left, mut right) = tokio::io::duplex(128 * 1024);
        let client = Mux::new(left, MuxConfig::default(), Mode::Client);
        client.close().await.unwrap();
        let mut bytes = [0u8; 10];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            right.read_exact(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read, frame::HEADER);
        assert_eq!(bytes[1], frame::GOAWAY);
    }

    #[tokio::test]
    async fn concurrent_open_both_sides() {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let client = Mux::new(left, MuxConfig::default(), Mode::Client);
        let server = Mux::new(right, MuxConfig::default(), Mode::Server);
        let (client_stream, server_stream) = tokio::join!(
            client.open(StreamKind::Sync),
            server.open(StreamKind::Control)
        );
        assert!(client_stream.is_ok());
        assert!(server_stream.is_ok());
    }

    #[tokio::test]
    async fn memory_bounded() {
        let (left, _right) = tokio::io::duplex(128 * 1024);
        let config = MuxConfig {
            max_streams: 1,
            ..MuxConfig::default()
        };
        let client = Mux::new(left, config, Mode::Client);
        let first = client.open(StreamKind::Sync).await.unwrap();
        drop(first);
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.open(StreamKind::Sync),
        )
        .await
        .unwrap()
        .is_err());
    }

    #[test]
    fn frame_header_is_ten_bytes() {
        assert_eq!(frame::HEADER, 10);
    }
}
