extern crate oath2;
extern crate log;
extern crate simple_logger;

use oath2::ctl;

pub fn main() {
    simple_logger::init().expect("could not init logger");
    ctl::start_controller("192.168.73.1:6653", |msg|{/* do nothing */}).expect("error in controller");
}