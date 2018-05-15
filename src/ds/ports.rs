// used to allow PortNo constants
#![allow(overflowing_literals)]

use super::super::err::*;
use super::hw_addr;
use std::convert::{TryFrom, Into};
use std::ffi::CString;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};

/// OpenFlow port struct length is 64 bytes.
pub const PORT_LENGTH: usize = 64;

/// OpenFlow port struct.
#[derive(Debug, PartialEq, Clone)]
pub struct Port {
    port_no: PortNumber,
    //pad 4 bytes
    hw_addr: hw_addr::EthernetAddress,
    //pad 2 bytes, 
    /// Null terminated 16 byte (including null) port name
    name: CString,

    /// Bitmap of PortConfig flags.
    config: PortConfig,
    /// Bitmap of PortState flags.
    state: PortState,

    /// Current features.
    curr: PortFeatures,
    /// Features being advertised by the port.
    advertised: PortFeatures,
    /// Features supported by the port.
    supported: PortFeatures,
    /// Features advertised by peer.
    peer: PortFeatures,

    /// Current port bitrate in kbps.
    curr_speed: u32,
    /// Max port bitrate in kbps.
    max_speed: u32,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PortNumber {
    Reserved(PortNo),
    NormalPort(u32),
}

impl TryFrom<u32> for PortNumber {
    type Error = Error;
    fn try_from(port_no: u32) -> Result<Self> {
        if port_no == 0 {
            bail!(ErrorKind::IllegalValue(0, stringify!(PortNumber)));
        }
        Ok(match PortNo::from_u32(port_no){
            Some(port) => PortNumber::Reserved(port),
            None => PortNumber::NormalPort(port_no),
        })
    }
}

impl Into<u32> for PortNumber {
    fn into(self) -> u32 {
        match self {
            PortNumber::Reserved(port_no) => port_no.to_u32().unwrap(),
            PortNumber::NormalPort(port_no) => port_no,
        }
    }
}

/// Port numbering. Ports are numbered starting from 1.
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum PortNo {
    /* Maximum number of physical and logical switch ports. */
    Max = 0xffffff00,
    /* Reserved OpenFlow Port (fake output "ports"). */
    /// Send the packet out the input port. This
    /// reserved port must be explicitly used
    /// in order to send back out of the input
    /// port. 
    InPort = 0xfffffff8, 
    /// Submit the packet to the first flow table
    /// NB: This destination port can only be
    /// used in packet-out messages. 
    Table = 0xfffffff9, 
    /// Process with normal L2/L3 switching. 
    Normal = 0xfffffffa, 
    /// All physical ports in VLAN, except input
    /// port and those blocked or link down. 
    Flood = 0xfffffffb, 
    /// All physical ports except input port. 
    All = 0xfffffffc, 
    /// Send to controller. 
    Controller = 0xfffffffd, 
    /// Local openflow "port". 
    Local = 0xfffffffe, 
    /// Wildcard port used only for flow mod
    /// (delete) and flow stats requests. Selects
    /// all flows regardless of output port
    /// (including flows with no output port). 
    Any = 0xffffffff, 
}


bitflags!{
    /// Flags to indicate behavior of the physical port. These flags are
    /// used in ofp_port to describe the current configuration. They are
    /// used in the ofp_port_mod message to configure the port's behavior.
    pub struct PortConfig: u32 {
        /// Port is administratively down. 
        const PORT_DOWN = 1 << 0;
        /// Drop all packets received by port. 
        const NO_RECV = 1 << 2;
        /// Drop packets forwarded to port. 
        const NO_FWD = 1 << 5;
        /// Do not send packet-in msgs for port. 
        const NO_PACKET_IN = 1 << 6; 
    }
}

bitflags! {
    /// Current state of the physical port. These are not configurable from
    ///  the controller.
    pub struct PortState: u32 {
        /// No physical link present.
        const LINK_DOWN = 1 << 0;
        /// Port is blocked 
        const BLOCKED = 1 << 1;
        /// Live for Fast Failover Group.
        const LIVE = 1 << 2;
    }
}

bitflags! {
    pub struct PortFeatures: u32 {
        /// 10 Mb half-duplex rate support. 
        const MB10_HD = 1 << 0; 
        /// 10 Mb full-duplex rate support. 
        const MB10_FD = 1 << 1;
        /// 100 Mb half-duplex rate support. 
        const MB100_HD = 1 << 2; 
        /// 100 Mb full-duplex rate support. 
        const MB100_FD = 1 << 3;
        /// 1 Gb half-duplex rate support. 
        const GB4_HD = 1 << 4; 
        /// 1 Gb full-duplex rate support. 
        const GB4_FD = 1 << 5;
        /// 10 Gb full-duplex rate support. 
        const GB10_FD = 1 << 6; 
        /// 40 Gb full-duplex rate support. 
        const GB40_FD = 1 << 7;
        /// 100 Gb full-duplex rate support. 
        const GB100_FD = 1 << 8;
        /// 1 Tb full-duplex rate support. 
        const TB1_FD = 1 << 9;
        /// Other rate, not in the list. 
        const OTHER = 1 << 10;

        /// Copper medium. 
        const COPPER = 1 << 11; 
        /// Fiber medium. 
        const FIBER = 1 << 12;
        /// Auto-negotiation. 
        const AUTONEG = 1 << 13;
        /// Pause. 
        const PAUSE = 1 << 14;
        /// Asymmetric pause. 
        const PAUSE_ASYM = 1 << 15;
    }
}