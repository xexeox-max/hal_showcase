use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

pub async fn connect(url: &str) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let normalized = normalize_url(url);
    let (stream, _) = connect_async(normalized.as_str())
        .await
        .map_err(|error| io::Error::other(format!("WebSocket handshake failed: {error}")))?;
    log::info!("WSS Transport: connected to {url}");
    Ok(stream)
}

pub fn normalize_url(url: &str) -> String {
    match url.strip_prefix("https://") {
        Some(rest) => format!("wss://{rest}"),
        None => url.to_string(),
    }
}

pub struct WsStream<S> {
    read: futures_util::stream::SplitStream<WebSocketStream<S>>,
    write: futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    pending_read: std::collections::VecDeque<Vec<u8>>,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: WebSocketStream<S>) -> Self {
        let (write, read) = stream.split();
        Self {
            read,
            write,
            pending_read: std::collections::VecDeque::new(),
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(bytes) = self.pending_read.pop_front() {
            let len = buf.remaining().min(bytes.len());
            buf.put_slice(&bytes[..len]);
            if len < bytes.len() {
                self.pending_read.push_front(bytes[len..].to_vec());
            }
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.read).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                let len = buf.remaining().min(bytes.len());
                buf.put_slice(&bytes[..len]);
                if len < bytes.len() {
                    self.pending_read.push_front(bytes[len..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Text(text)))) => {
                let bytes = text.into_bytes();
                let len = buf.remaining().min(bytes.len());
                buf.put_slice(&bytes[..len]);
                if len < bytes.len() {
                    self.pending_read.push_front(bytes[len..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Frame(frame)))) => {
                let bytes = frame.payload().to_vec();
                let len = buf.remaining().min(bytes.len());
                buf.put_slice(&bytes[..len]);
                if len < bytes.len() {
                    self.pending_read.push_front(bytes[len..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Ping(_)))) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Ok(Message::Pong(_)))) | Poll::Ready(Some(Ok(Message::Close(_)))) => {
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.write).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut self.write).start_send(Message::Binary(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(error) => Poll::Ready(Err(io::Error::other(error))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
