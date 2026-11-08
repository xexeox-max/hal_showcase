use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::mux::{DriverCommand, StreamKind};

pub struct MuxStream {
    id: u32,
    kind: StreamKind,
    read_rx: mpsc::UnboundedReceiver<Option<Bytes>>,
    command_tx: std::sync::Arc<mpsc::Sender<DriverCommand>>,
    read_buf: BytesMut,
    eof: bool,
    close_sent: bool,
    pending_write: Option<
        Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<DriverCommand>>> + Send>>,
    >,
    pending_count: usize,
    pending_close: Option<
        Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<DriverCommand>>> + Send>>,
    >,
}

impl MuxStream {
    pub(crate) fn new(
        id: u32,
        kind: StreamKind,
        read_rx: mpsc::UnboundedReceiver<Option<Bytes>>,
        command_tx: std::sync::Arc<mpsc::Sender<DriverCommand>>,
    ) -> Self {
        Self {
            id,
            kind,
            read_rx,
            command_tx,
            read_buf: BytesMut::new(),
            eof: false,
            close_sent: false,
            pending_write: None,
            pending_count: 0,
            pending_close: None,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn kind(&self) -> StreamKind {
        self.kind
    }

    pub async fn close(mut self) -> anyhow::Result<()> {
        if !self.close_sent {
            self.command_tx
                .send(DriverCommand::Close(self.id))
                .await
                .map_err(|_| anyhow::anyhow!("mux driver closed"))?;
            self.close_sent = true;
        }
        Ok(())
    }

    pub async fn reset(self) -> anyhow::Result<()> {
        self.command_tx
            .send(DriverCommand::Reset(self.id))
            .await
            .map_err(|_| anyhow::anyhow!("mux driver closed"))?;
        Ok(())
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let count = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf.split_to(count));
            let _ = self
                .command_tx
                .try_send(DriverCommand::Consumed(self.id, count as u32));
            return std::task::Poll::Ready(Ok(()));
        }
        if self.eof {
            return std::task::Poll::Ready(Ok(()));
        }

        match std::pin::Pin::new(&mut self.read_rx).poll_recv(cx) {
            std::task::Poll::Ready(Some(Some(bytes))) => {
                self.read_buf.extend_from_slice(&bytes);
                let count = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf.split_to(count));
                let _ = self
                    .command_tx
                    .try_send(DriverCommand::Consumed(self.id, count as u32));
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(None)) | std::task::Poll::Ready(None) => {
                self.eof = true;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.close_sent {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux stream closed",
            )));
        }

        if let Some(mut future) = this.pending_write.take() {
            match future.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    let count = this.pending_count;
                    this.pending_count = 0;
                    return std::task::Poll::Ready(Ok(count));
                }
                std::task::Poll::Ready(Err(_)) => {
                    this.pending_count = 0;
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux driver closed",
                    )));
                }
                std::task::Poll::Pending => {
                    this.pending_write = Some(future);
                    return std::task::Poll::Pending;
                }
            }
        }

        let count = buf.len().min(32 * 1024);
        let command = DriverCommand::Data(this.id, Bytes::copy_from_slice(&buf[..count]));
        let tx = std::sync::Arc::clone(&this.command_tx);
        this.pending_count = count;
        this.pending_write = Some(Box::pin(async move { tx.send(command).await }));

        let Some(mut future) = this.pending_write.take() else {
            this.pending_count = 0;
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux write state unavailable",
            )));
        };
        match future.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(())) => {
                this.pending_count = 0;
                std::task::Poll::Ready(Ok(count))
            }
            std::task::Poll::Ready(Err(_)) => {
                this.pending_count = 0;
                std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux driver closed",
                )))
            }
            std::task::Poll::Pending => {
                this.pending_write = Some(future);
                std::task::Poll::Pending
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(mut future) = self.pending_close.take() {
            match future.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => self.close_sent = true,
                std::task::Poll::Ready(Err(_)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux driver closed",
                    )));
                }
                std::task::Poll::Pending => {
                    self.pending_close = Some(future);
                    return std::task::Poll::Pending;
                }
            }
        } else if !self.close_sent {
            let tx = std::sync::Arc::clone(&self.command_tx);
            let command = DriverCommand::Close(self.id);
            self.pending_close = Some(Box::pin(async move { tx.send(command).await }));
            let Some(mut future) = self.pending_close.take() else {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux close state unavailable",
                )));
            };
            match future.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => self.close_sent = true,
                std::task::Poll::Ready(Err(_)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux driver closed",
                    )));
                }
                std::task::Poll::Pending => {
                    self.pending_close = Some(future);
                    return std::task::Poll::Pending;
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}
