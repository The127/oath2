extern crate log;
extern crate oath2;
extern crate simple_logger;

use oath2::ctl;
use oath2::ds;

pub fn main() {
    simple_logger::init().expect("could not init logger");
    ctl::start_controller("192.168.73.1:6653", |msg| {
        //handle packet in here
        //this is a simple hub implementation
        // get packet in payload from msg
        if let ds::OfPayload::PacketIn(packet_in) = msg.msg.payload() {
            let mut actions = Vec::new();
            //flood action
            actions.push(Into::<ds::actions::ActionHeader>::into(
                ds::actions::PayloadOutput {
                    port: ds::ports::PortNumber::Reserved(ds::ports::PortNo::Flood),
                    max_len: 0,
                },
            ));
            let mut actions_len = 0;
            for action in &actions {
                actions_len += action.len();
            }
            let payload_packet_out = ds::packet_out::PacketOut {
                buffer_id: packet_in.buffer_id,
                in_port: ds::ports::PortNumber::Reserved(ds::ports::PortNo::Controller),
                actions_len: actions_len,
                actions: actions,
                data: packet_in.ethernet_frame.clone(),
            };
            let response = ds::OfMsg::generate(
                *msg.msg.header().xid(),
                ds::OfPayload::PacketOut(payload_packet_out),
            );
            msg.reply_ch
                .send(response)
                .expect("could not send packet_in response");
        }
    }).expect("error in controller");
}
/*//handle packet in here
//this is a simple hub implementation
// get packet in payload from msg
if let ds::OfPayload::PacketIn(packet_in) = msg.msg.payload {
    let mut actions = Vec::new();
    //flood action
    actions.push(Into::<ds::actions::ActionHeader>::into(ds::actions::PayloadOutput{
        port: ds::ports::PortNoWrapper::Reserved(ds::ports::PortNo::Flood),
        max_len: ::std::u16::MAX,
    }));
    let mut actions_len = 0;
    for action in &actions {
        actions_len += action.len;
    }
    let payload_packet_out = ds::packet_out::PacketOut{
        buffer_id: packet_in.buffer_id,
        in_port: ds::ports::PortNoWrapper::Reserved(ds::ports::PortNo::Controller),
        actions_len: actions_len,
        actions: actions,
        data: packet_in.ethernet_frame,
    };
    let header = ds::header::Header{
        version: msg.msg.header.version,
        ttype: ds::header::Type::PacketOut,
        length: ds::header::HEADER_LENGTH as u16 
            + ds::packet_out::PACKET_OUT_LEN as u16 
            + payload_packet_out.actions_len as u16
            + payload_packet_out.data.len() as u16,
        xid: msg.msg.header.xid,
    };
    let resp = ds::OfMsg{
        header: header,
        payload: ds::OfPayload::PacketOut(payload_packet_out),
    };
    msg.ch.send(resp).expect("could not send packet_in response");
)*/
