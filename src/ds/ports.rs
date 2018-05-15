// used to allow PortNo constants
#![allow(overflowing_literals)]

use super::super::err::*;
use super::hw_addr;
use std::convert::{TryFrom, Into};
use std::ffi::CString;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};

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

impl Into<Result<u32>> for PortNumber {
    fn into(self) -> Result<u32> {
        Ok(match self {
            PortNumber::Reserved(port_no) => port_no.to_u32().unwrap(),
            PortNumber::NormalPort(port_no) => port_no,
        })
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