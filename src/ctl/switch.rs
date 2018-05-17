use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Sender};
use std::thread;

use super::super::ds;
use super::super::err::*;

pub struct IncomingMsg {
    pub reply_ch: Sender<ds::OfMsg>,
    pub msg: ds::OfMsg,
}

pub fn start_switch_connection(stream_in: TcpStream, ctl_ch: Sender<IncomingMsg>) -> Result<()> {
    let stream_out = stream_in.try_clone()?;
    let (send, recv) = channel::<ds::OfMsg>();

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
                let payload_bytes = &read_bytes(&mut stream_in, *&header.payload_length() as usize)
                    .expect("could not read payload bytes")[..];
                info!("Read Payload Bytes");
                let payload = match &header.ttype() {
                    ds::Type::Hello => Some(ds::OfPayload::Hello),
                    ds::Type::Error => Some(ds::OfPayload::Error),
                    ds::Type::EchoRequest => Some(ds::OfPayload::EchoRequest),
                    // these should be automatic later, eg.: ds::packet_in::PacketIn::try_from(payload_bytes)?.into(),
                    ds::Type::Experimenter => {
                        error!("No experimenter support (yet?)");
                        None
                    }
                    ds::Type::FeaturesReply => Some(ds::OfPayload::FeaturesReply(
                        ds::features::SwitchFeatures::try_from(&payload_bytes[..])
                            .expect("error while try_from SwitchFeatures"),
                    )),
                    ds::Type::GetConfigReply => Some(ds::OfPayload::GetConfigReply(
                        ds::switch_config::SwitchConfig::try_from(&payload_bytes[..])
                            .expect("error while try_from SwitchConfig"),
                    )),
                    ds::Type::PacketIn => Some(ds::OfPayload::PacketIn(
                        ds::packet_in::PacketIn::try_from(&payload_bytes[..])
                            .expect("error while try_from PacketIn"),
                    )),
                    ds::Type::FlowRemoved => Some(ds::OfPayload::FlowRemoved(
                        ds::flow_removed::FlowRemoved::try_from(&payload_bytes[..])
                            .expect("error while try_from FlowRemoved"),
                    )),
                    ds::Type::PortStatus => Some(ds::OfPayload::PortStatus(
                        ds::port_status::PortStatus::try_from(&payload_bytes[..])
                            .expect("error while try_from PortStatus"),
                    )),
                    ds::Type::MultipartReply => {
                        error!("No MultipartReply support (yet?)");
                        None
                    }
                    ds::Type::BarrierReply => Some(ds::OfPayload::BarrierReply),
                    ds::Type::QueueGetConfigReply => Some(ds::OfPayload::QueueGetConfigReply(
                        ds::queue_config::QueueGetConfigReply::try_from(&payload_bytes[..])
                            .expect("error while try_from QueueGetConfigReply"),
                    )),
                    ds::Type::RoleReply => Some(ds::OfPayload::RoleReply(
                        ds::role::Role::try_from(&payload_bytes[..])
                            .expect("error while try_from Role"),
                    )),
                    ds::Type::GetAsyncReply => Some(ds::OfPayload::GetAsyncReply(
                        ds::async::Async::try_from(&payload_bytes[..])
                            .expect("error while try_from Async"),
                    )),
                    _ => {
                        error!("received not allowed ofmsg type {:?}", header.ttype());
                        None
                    }
                };
                info!("Read Payload: {:?}.", payload);

                // if the payload is supported
                match payload {
                    Some(payload) => {
                        // send channel message (with sender channel in message)
                        ctl_ch
                            .send(IncomingMsg {
                                reply_ch: send.clone(),
                                msg: ds::OfMsg::new(header, payload),
                            })
                            .expect("error while sending msg via channel to controller");
                    }
                    _ => (),
                }
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
                        let write_slice = &Into::<Vec<u8>>::into(of_msg)[..];
                        stream_out
                            .write_all(write_slice)
                            .expect("could not write bytes to stream");
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
        let bytes_to_read: usize = ::std::cmp::min(len - read, READ_BUFFER_SIZE);
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
