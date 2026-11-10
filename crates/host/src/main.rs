mod bridge;
mod native;

use std::error::Error;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::process;
use std::sync::{Arc, mpsc::{self, SyncSender}};
use std::time::Duration;
use naga_ipc::{BootTicket, Frame, Handler, PROTOCOL_VERSION, Peer, Request, RpcError, RpcResult, read_frame, write_frame};
use bridge::Bridge;
use native::NativeModule;

struct Work {
    request: Request,
    response: SyncSender<RpcResult>
}

struct Dispatcher {
    sender: SyncSender<Work>,
    timeout: Duration
}

impl Handler for Dispatcher {
    fn handle(&self, request: Request) -> RpcResult {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender.try_send(Work { request, response: sender })
            .map_err(|_| RpcError::new("busy", "module executor queue unavailable"))?;
        receiver.recv_timeout(self.timeout)
            .unwrap_or_else(|_| Err(RpcError::new("timeout", "native module callback timed out")))
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let ticket: BootTicket = read_frame(&mut io::stdin().lock())?;
    if ticket.protocol != PROTOCOL_VERSION || ticket.token.len() != 64 {
        return Err("invalid bootstrap protocol".into())
    }
    let address: SocketAddr = ticket.address.parse()?;
    if !address.ip().is_loopback() { return Err("IPC bootstrap must use loopback".into()) }
    let timeout = Duration::from_millis(ticket.request_timeout_ms);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_frame(&mut stream, &Frame::Hello {
        protocol: PROTOCOL_VERSION, token: ticket.token.clone(), key: ticket.key.clone()
    })?;
    if !matches!(read_frame::<Frame>(&mut stream)?, Frame::Accepted { protocol: PROTOCOL_VERSION }) {
        return Err("IPC handshake rejected".into())
    }
    stream.set_read_timeout(None)?;
    eprintln!("naga-host: trace: IPC authenticated");
    let (sender, receiver) = mpsc::sync_channel(64);
    let peer = Peer::attach(stream, Arc::new(Dispatcher { sender, timeout }))?;
    let bridge = Box::leak(Box::new(Bridge::new(peer.clone(), &ticket, timeout)?));
    let api = Box::leak(Box::new(bridge.api()));
    let mut module = NativeModule::load(&ticket, api)?;
    eprintln!("naga-host: trace: native ABI initialized");
    peer.call(Request::HostReady, timeout)?;
    eprintln!("naga-host: trace: ready");
    while !peer.is_closed() {
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(work) => {
                let result = module.handle(work.request);
                let _ = work.response.send(result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break
        }
    }
    Ok(())
}

fn main() {
    let status = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("naga-host: {err}");
            1
        }
    };
    process::exit(status);
}
