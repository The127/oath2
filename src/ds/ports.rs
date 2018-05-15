// used to allow PortNo constants
#![allow(overflowing_literals)]

use super::super::err::*;
use super::hw_addr;
use std::convert::{TryFrom, Into};
use std::ffi::CString;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io::{SeekFrom, Seek, Cursor, Write};
use std::path;

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

impl<'a> TryFrom<&'a [u8]> for Port {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        // check if bytes have correct length
        if bytes.len() != PORT_LENGTH {
            bail!(ErrorKind::InvalidSliceLength(
                PORT_LENGTH,
                bytes.len(),
                stringify!(Port),
            ));
        }
        let mut cursor = Cursor::new(bytes);

        // read raw version val
        let port_no = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let port_no = PortNumber::try_from(port_no)?;

        //works because big endian format
        let hw_addr_slice = &bytes[8..14];

        //works because big endian format
        let name_slice = &bytes[16..32];
        let name = unsafe {
            CString::from_vec_unchecked(Vec::from(name_slice))
        };

        //put cursor to correct position after string (32 bytes)
        cursor.seek(SeekFrom::Start(32)).unwrap();

        let config = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port config!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let config = PortConfig::from_bits(config)
            .ok_or::<Error>(ErrorKind::UnknownValue(config as u64, stringify!(PortConfig)).into())?;

        let state = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port state!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let state = PortState::from_bits(state)
            .ok_or::<Error>(ErrorKind::UnknownValue(state as u64, stringify!(PortState)).into())?;

        let curr = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port curr!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let curr = PortFeatures::from_bits(curr)
            .ok_or::<Error>(ErrorKind::UnknownValue(curr as u64, stringify!(PortFeatures)).into())?;

        let advertised = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port advertised!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let advertised = PortFeatures::from_bits(advertised)
            .ok_or::<Error>(ErrorKind::UnknownValue(advertised as u64, stringify!(PortFeatures)).into())?;

        let supported = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port supported!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let supported = PortFeatures::from_bits(supported)
            .ok_or::<Error>(ErrorKind::UnknownValue(supported as u64, stringify!(PortFeatures)).into())?;

        let peer = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read port peer!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let peer = PortFeatures::from_bits(peer)
            .ok_or::<Error>(ErrorKind::UnknownValue(peer as u64, stringify!(PortFeatures)).into())?;

        Ok(Port{
            port_no: port_no,
            hw_addr: hw_addr::from_slice_eth(hw_addr_slice)?,
            name: name,
            config: config,
            state: state,
            curr: curr,
            advertised: advertised,
            supported: supported,
            peer: peer,
            curr_speed: cursor.read_u32::<BigEndian>().chain_err(|| {
                let err_msg = format!("Could not read port curr_speed!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
                error!("{}", err_msg);
                err_msg
            })?,
            max_speed: cursor.read_u32::<BigEndian>().chain_err(|| {
                let err_msg = format!("Could not read port max_speed!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
                error!("{}", err_msg);
                err_msg
            })?,
        })
    }
}

impl Into<Vec<u8>> for Port {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.port_no.into()).unwrap();
        // pad 4 bytes 
        res.write_u32::<BigEndian>(0).unwrap();
        res.extend_from_slice(&self.hw_addr[..]);
        // pad 2 bytes
        res.write_u16::<BigEndian>(0).unwrap();
        // dont check validity of CString (length) here
        // instead do so in the creation method (if one exists)
        let mut bytes_written = res.write(&self.name.into_bytes()[..]).unwrap();
        //pad with 0 bytes until 16 bytes are written
        while bytes_written < 16 {
            res.write_u8(0u8).unwrap();
            bytes_written += 1;
        }
        res.write_u32::<BigEndian>(self.config.bits()).unwrap();
        res.write_u32::<BigEndian>(self.state.bits()).unwrap();
        res.write_u32::<BigEndian>(self.curr.bits()).unwrap();
        res.write_u32::<BigEndian>(self.advertised.bits()).unwrap();
        res.write_u32::<BigEndian>(self.supported.bits()).unwrap();
        res.write_u32::<BigEndian>(self.peer.bits()).unwrap();
        res.write_u32::<BigEndian>(self.curr_speed).unwrap();
        res.write_u32::<BigEndian>(self.max_speed).unwrap();
        res
    }
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