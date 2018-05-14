use std::net::{TcpListener, ToSocketAddrs};
use std::sync::mpsc::channel;
use std::thread;

use super::ds;
use super::err::*;

pub mod switch;

/// starts the controller at the given address (eg. "127.0.0.1:6653")
/// the given handler function will not receive hellos or echo requests or similar messages
/// these are handled automatically by the controller
/// also the controller will create a flow in the switch that sends all
/// unknown messages to the controller automatically on connection setup
/// this function does not return
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
                    // match msg type and automatically handle special types (hello, ...)
                    match of_msg.msg.header().ttype() {
                        ds::Type::Hello => handle_hello(of_msg),
                        ds::Type::EchoRequest => handle_echo_request(of_msg),
                        _ => handler(of_msg),
                    }
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
            switch::start_switch_connection(stream, tcp_s.clone());
        }
    }

    // should never happen
    // but makes the compiler happy :)
    Ok(())
}

fn handle_hello(msg: switch::IncomingMsg) {
    let response = ds::OfMsg::generate(*msg.msg.header().xid(), ds::OfPayload::Hello);
    msg.reply_ch
        .send(response)
        .expect("could not send hello response");
}

fn handle_echo_request(msg: switch::IncomingMsg) {
    let response = ds::OfMsg::generate(*msg.msg.header().xid(), ds::OfPayload::EchoResponse);
    msg.reply_ch
        .send(response)
        .expect("could not send hello response");
}
