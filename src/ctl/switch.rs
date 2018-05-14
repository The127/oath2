use std::convert::TryFrom;
use std::io::Read;
use std::net::TcpStream;
use std::sync::mpsc::{channel, Sender};
use std::thread;

use super::super::ds;
use super::super::err::*;

pub struct IncomingMsg {
    pub reply_ch: Sender<()>,
    pub msg: ds::OfMsg,
}

pub fn start_switch_connection(stream_in: TcpStream, ctl_ch: Sender<IncomingMsg>) -> Result<()> {
    let stream_out = stream_in.try_clone()?;
    let (send, recv) = channel::<()>();

    // start switch input thread
    info!("Starting input thread for: {:?}.", stream_in.peer_addr());
    thread::Builder::new()
        .name(format!("Switch-In {:?}", stream_in.peer_addr()).to_string())
        .spawn(move || {
            let mut stream_in = stream_in;
            loop {
                // read input header + log
                let header_bytes = read_bytes(&mut stream_in, ds::HEADER_LENGTH)
                    .expect("could not read header bytes");
                let header = ds::Header::try_from(&header_bytes[..])
                    .expect("could not convert header bytes to actual header");
                info!("Read OfHeader: {:?}.", header);

                // read input payload + log
                let payload_bytes = read_bytes(&mut stream_in, *&header.payload_length() as usize)
                    .expect("could not read payload bytes");
                let payload = match &header.ttype() {
                    ds::Type::Hello => ds::OfPayload::Hello,
                    ds::Type::Error => ds::OfPayload::Error,
                    ds::Type::EchoRequest => ds::OfPayload::EchoRequest,
                    ds::Type::Experimenter => ds::OfPayload::Experimenter,
                    ds::Type::FeaturesReply => ds::OfPayload::FeaturesReply,
                    ds::Type::GetConfigReply => ds::OfPayload::GetConfigReply,
                    ds::Type::PacketIn => ds::OfPayload::PacketIn,
                    ds::Type::FlowRemoved => ds::OfPayload::FlowRemoved,
                    ds::Type::PortStatus => ds::OfPayload::PortStatus,
                    ds::Type::MultipartReply => ds::OfPayload::MultipartReply,
                    ds::Type::BarrierReply => ds::OfPayload::BarrierReply,
                    ds::Type::QueueGetConfigReply => ds::OfPayload::QueueGetConfigReply,
                    ds::Type::RoleReply => ds::OfPayload::RoleReply,
                    ds::Type::GetAsyncReply => ds::OfPayload::GetAsyncReply,
                    ttype => {
                        error!(
                            "received not allowed ofmsg type {:?}",
                            header.ttype()
                        );
                        panic!(
                            "received not allowed ofmsg type {:?}",
                            header.ttype()
                        );
                    }
                };
                info!("Read Payload: {:?}.", payload);

                // send channel message (with sender channel in message)
                ctl_ch.send(IncomingMsg{
                    reply_ch: send.clone(),
                    msg: ds::OfMsg::new(
                        header,
                        payload,
                    ),
                }).expect("error while sending msg via channel to controller");
            }
        })?;

    // start switch output thread
    info!("Starting output thread for: {:?}.", stream_out.peer_addr());
    thread::Builder::new()
        .name(format!("Switch-In {:?}", stream_out.peer_addr()).to_string())
        .spawn(move || {
            let mut stream_out = stream_out;
            loop {
                // wait for a message to send from controller
                match recv.recv() {
                    Ok(of_msg) => {
                        // send message to switch
                        info!("Sending {:?} to: {:?}.", of_msg, stream_out.peer_addr());
                    }
                    Err(err) => panic!(err),
                }
            }
        })?;

    // function successfull
    Ok(())
}

// maybe make this modifiable from outside?
pub const READ_BUFFER_SIZE: usize = 128;

/// used to read exact number of bytes from stream including any zero bytes
fn read_bytes(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut res = Vec::new();
    let mut buffer = [0u8; READ_BUFFER_SIZE];
    let mut read: usize = 0;
    while read < len {
        let bytes_to_read: usize = (len - read) % READ_BUFFER_SIZE;
        let mut buf_slice = &mut buffer[0..bytes_to_read];
        read_exact(stream, &mut buf_slice).expect("could not read bytes from stream");
        read += bytes_to_read;
        res.extend_from_slice(buf_slice);
    }
    Ok(res)
}

/// used inside read_bytes to fill a slice from stream input data including any zero bytes
fn read_exact(
    reader: &mut TcpStream,
    mut buf: &mut [u8],
) -> ::std::result::Result<(), ::std::io::Error> {
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(e) => return Err(e),
        }
    }
    if !buf.is_empty() {
        Ok(())
    } else {
        Ok(())
    }
}
