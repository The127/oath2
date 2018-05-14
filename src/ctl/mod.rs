use std::net::{TcpListener, ToSocketAddrs};
use std::sync::mpsc::channel;
use std::thread;

use super::err::*;

pub mod switch;

pub fn start_controller<A, F>(addr: A, handler: F) -> Result<()>
where
    A: ToSocketAddrs,
    F: Fn(switch::IncomingMsg) + Send + 'static,
{
    // try starting tcp listener at given address
    info!("Starting tcp listener.");
    let tcp_listener = TcpListener::bind(addr)?;
    info!(
        "Tcp listener successfully started at {:?}.",
        tcp_listener.local_addr()
    );

    let (tcp_s, tcp_r) = channel::<switch::IncomingMsg>();

    // start handler thread
    info!("Starting handler thread.");
    thread::Builder::new()
        .name("Handler-Thread".to_string())
        .spawn(move || loop {
            match tcp_r.recv() {
                Ok(of_msg) => {
                    info!("Handling msg: {:?}.", of_msg.msg);
                    //TODO: match msg type and automatically handle special types (hello, ...)
                    handler(of_msg);
                }
                Err(err) => panic!(err),
            }
        })?;

    // endless loop -> accept incoming switches
    info!("Starting tcp accept.");
    for stream in tcp_listener.incoming() {
        // try to open connection
        // silently fail
        if let Ok(stream) = stream {
            info!("Tcp connection from: {:?}.", stream.peer_addr());
            // start new connection to switch
            // give copy of tcp_s to inform handler of new messages
        }
    }

    // should never happen
    // but makes the compiler happy :)
    Ok(())
}
