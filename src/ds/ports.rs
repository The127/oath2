use std::convert::{TryFrom, Into};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io::{SeekFrom, Seek, Cursor, Write};
use super::super::err::*;
use super::hw_addr;
use std::ffi::CString;

/// OpenFlow port struct length is 64 bytes.
pub const PORT_LENGTH: usize = 64;

/// OpenFlow port struct.
#[derive(Debug, PartialEq, Clone)]
pub struct Port {
    port_no: PortNoWrapper,
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
            return Err(ErrorKind::InvalidSliceLength(
                PORT_LENGTH,
                bytes.len(),
                stringify!(Port),
            ).into());
        }
        let mut cursor = Cursor::new(bytes);

        // read raw version val
        let port_no = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let port_no = PortNoWrapper::try_from(port_no)?;

        //works because big endian format
        let hw_addr = &bytes[8..14];

        //works because big endian format
        let name_slice = &bytes[16..32];
        let name = unsafe {
            CString::from_vec_unchecked(Vec::from(name_slice))
        };

        //put cursor to correct position
        cursor.seek(SeekFrom::Start(32)).unwrap();

        // read raw version val
        let config = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let config = match PortConfig::from_bits(config){
            Some(config) => config,
            None => return Err(ErrorKind::UnknownValue(config as u64, stringify!(PortConfig)).into()),
        };

        // read raw version val
        let state = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let state = match PortState::from_bits(state){
            Some(state) => state,
            None => return Err(ErrorKind::UnknownValue(state as u64, stringify!(PortState)).into()),
        };

        // read raw version val
        let curr = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let curr = match PortFeatures::from_bits(curr){
            Some(curr) => curr,
            None => return Err(ErrorKind::UnknownValue(curr as u64, stringify!(PortFeatures)).into()),
        };

        // read raw version val
        let advertised = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let advertised = match PortFeatures::from_bits(advertised){
            Some(advertised) => advertised,
            None => return Err(ErrorKind::UnknownValue(advertised as u64, stringify!(PortFeatures)).into()),
        };

        // read raw version val
        let supported = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let supported = match PortFeatures::from_bits(supported){
            Some(supported) => supported,
            None => return Err(ErrorKind::UnknownValue(supported as u64, stringify!(PortFeatures)).into()),
        };

        // read raw version val
        let peer = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let peer = match PortFeatures::from_bits(peer){
            Some(peer) => peer,
            None => return Err(ErrorKind::UnknownValue(peer as u64, stringify!(PortFeatures)).into()),
        };

        Ok(Port{
            port_no: port_no,
            hw_addr: hw_addr::from_slice(hw_addr),
            name: name,
            config: config,
            state: state,
            curr: curr,
            advertised: advertised,
            supported: supported,
            peer: peer,
            curr_speed: cursor.read_u32::<BigEndian>().unwrap(),
            max_speed: cursor.read_u32::<BigEndian>().unwrap(),
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
        let mut bytes_written = res.write(&self.name.into_bytes()[..]).unwrap();
        //pad with 0 bytes intil 16 bytes are written
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
pub enum PortNoWrapper {
    Port(u32),
    Reserved(PortNo),
}

impl TryFrom<u32> for PortNoWrapper {
    type Error = Error;
    fn try_from(raw: u32) -> Result<Self> {
        if raw == 0{
            return Err(ErrorKind::UnknownValue(raw as u64, stringify!(PortNoWrapper)).into());
        }
        Ok(match PortNo::from_u32(raw) {
            Some(port_no) => PortNoWrapper::Reserved(port_no),
            None => PortNoWrapper::Port(raw),
        })
    }
}

impl Into<u32> for PortNoWrapper {
    fn into(self) -> u32 {
        match self {
            PortNoWrapper::Port(port_no) => port_no,
            PortNoWrapper::Reserved(port_no) => port_no.to_u32().unwrap(),
        }
    }
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

#[cfg(test)]
mod tests{
    use super::*;
    use super::super::hw_addr;

    #[test]
    fn tryfrom_smallslice() {
        assert!(Port::try_from(&[0u8;PORT_LENGTH-1][..]).is_err());
    }
    
    #[test]
    fn tryfrom_bigslice() {
        assert!(Port::try_from(&[0u8;PORT_LENGTH+1][..]).is_err());
    }

    #[test]
    fn into_length(){
        let p = Port{
            port_no: PortNoWrapper::Port(1),
            hw_addr: hw_addr::from_slice(&[0u8; 6]),
            name: ::std::ffi::CString::new(b"exactly15bytesa".to_vec()).expect("error while creating CString for test"),
            config: PortConfig::empty(),
            state: PortState::empty(),
            curr: PortFeatures::MB10_HD,
            advertised: PortFeatures::MB10_HD,
            supported: PortFeatures::MB10_HD,
            peer: PortFeatures::MB10_HD,
            curr_speed: 7,
            max_speed: 8,
        };
        let vec: Vec<u8> = p.into();
        assert_eq!(super::PORT_LENGTH, vec.len());
    }

    #[test]
    fn into_tryfrom() {
        let testee = Port{
            port_no: PortNoWrapper::Port(1),
            hw_addr: hw_addr::from_slice(&[0u8; 6]),
            name: ::std::ffi::CString::new(b"exactly15bytesa".to_vec()).expect("error while creating CString for test"),
            config: PortConfig::empty(),
            state: PortState::empty(),
            curr: PortFeatures::MB10_HD,
            advertised: PortFeatures::MB10_HD,
            supported: PortFeatures::MB10_HD,
            peer: PortFeatures::MB10_HD,
            curr_speed: 7,
            max_speed: 8,
        };
        // create 2 byte arrays and 2 from ports
        // because else the CStrings dont have a null at the end
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = Port::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        let bytes2 = Into::<Vec<u8>>::into(from.clone());
        let from2 = Port::try_from(&bytes2[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(from2, from);
        assert_eq!(PORT_LENGTH, bytes.len());
        assert_eq!(PORT_LENGTH, bytes2.len());
    }
}
