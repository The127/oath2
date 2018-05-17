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
            /*let payload_packet_out = ds::packet_out::PacketOut {
                buffer_id: packet_in.buffer_id,
                in_port: ds::ports::PortNumber::Reserved(ds::ports::PortNo::Controller),
                actions_len: ds::actions::calc_actions_len(&actions),
                actions: actions,
                data: packet_in.ethernet_frame.clone(),
            };*/
            let payload_packet_out = ds::packet_out::PacketOut::new(
                packet_in.buffer_id,
                ds::ports::PortNo::Controller.into(),
                actions,
                packet_in.ethernet_frame.clone(),
            );

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
