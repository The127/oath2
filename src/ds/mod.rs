use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::Cursor;

use super::err::*;
use std::path;

pub mod flow_match;
pub mod hw_addr;
pub mod packet_queue;
pub mod ports;
pub mod flow_instructions;

/// defines an OpenFlow message
/// header + payload
#[derive(Getters, Debug)]
pub struct OfMsg {
    #[get = "pub"]
    header: Header,
    #[get = "pub"]
    payload: OfPayload,
}

impl OfMsg {
    pub fn new(header: Header, payload: OfPayload) -> Self {
        OfMsg {
            header: header,
            payload: payload,
        }
    }

    pub fn generate(xid: u32, payload: OfPayload) -> Self {
        OfMsg {
            header: payload.generate_header(xid),
            payload: payload,
        }
    }
}

impl Into<Vec<u8>> for OfMsg {
    fn into(self) -> Vec<u8> {
        let mut vec = Into::<Vec<u8>>::into(self.header);
        vec.extend_from_slice(&Into::<Vec<u8>>::into(self.payload)[..]);
        vec
    }
}

/// OpenFlow message header length is 8 bytes.
pub const HEADER_LENGTH: usize = 8;

/// OpenFlow header struct.
#[derive(Getters, Debug, PartialEq, Clone)]
pub struct Header {
    /// OpenFlow version identifier
    #[get = "pub"]
    version: Version,
    /// OpenFlow message  type
    #[get = "pub"]
    ttype: Type,
    /// length of message including this header
    #[get = "pub"]
    length: u16,
    /// Transaction id associated with this packet.
    /// Replies use the same id as was in the request
    /// to facilitate pairing.
    #[get = "pub"]
    xid: u32,
}

/// Implementation of OpenFlow header struct
impl Header {
    /// returns the length of the payload  inbytes
    /// equivalent to the length in the header - HEADER_LENGTH
    pub fn payload_length(&self) -> u16 {
        // self.length is length of whole message including header length
        // therefore subtract the constant length of an OpenFlow header
        // to get the payload length in bytes
        self.length - (HEADER_LENGTH as u16)
    }
}

impl<'a> TryFrom<&'a [u8]> for Header {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        // check if bytes have correct length
        if bytes.len() != HEADER_LENGTH {
            bail!(ErrorKind::InvalidSliceLength(
                HEADER_LENGTH,
                bytes.len(),
                stringify!(Header),
            ));
        }
        let mut cursor = Cursor::new(bytes);

        let version_raw = cursor.read_u8().chain_err(|| {
            let err_msg = format!(
                "Could not read header version!{}Cursor: {:?}",
                path::MAIN_SEPARATOR,
                cursor
            );
            error!("{}", err_msg);
            err_msg
        })?;
        let version = Version::from_u8(version_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(version_raw as u64, stringify!(Version)).into(),
        )?;

        let ttype_raw = cursor.read_u8().chain_err(|| {
            let err_msg = format!(
                "Could not read header type!{}Cursor: {:?}",
                path::MAIN_SEPARATOR,
                cursor
            );
            error!("{}", err_msg);
            err_msg
        })?;
        let ttype = Type::from_u8(ttype_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(ttype_raw as u64, stringify!(Type)).into())?;

        // build result
        Ok(Header {
            version: version,
            ttype: ttype,
            length: cursor.read_u16::<BigEndian>().chain_err(|| {
                let err_msg = format!(
                    "Could not read header length!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
            xid: cursor.read_u32::<BigEndian>().chain_err(|| {
                let err_msg = format!(
                    "Could not read header xid!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
        })
    }
}

impl Into<Vec<u8>> for Header {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.version.to_u8().unwrap()).unwrap();
        res.write_u8(self.ttype.to_u8().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.length).unwrap();
        res.write_u32::<BigEndian>(self.xid).unwrap();
        res
    }
}

/// OpenFlow Version enum.
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum Version {
    /// indicates OpenFlow version 1.0
    V1_0 = 0x01,
    /// indicates OpenFlow version 1.1
    V1_1 = 0x02,
    /// indicates OpenFlow version 1.2
    V1_2 = 0x03,
    /// indicates OpenFlow version 1.3
    V1_3 = 0x04,
    /// indicates OpenFlow version 1.4
    V1_4 = 0x05,
}

/// Enum of OpenFlow message types.
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum Type {
    /* Immutable messages. */
    /// Hello message sent by switch and controller
    /// directly after establishing a connection.
    /// Symmetric message.
    Hello = 0,
    /// Symmetric message
    Error = 1,
    /// Symmetric message
    EchoRequest = 2,
    /// Symmetric message
    EchoReply = 3,
    /// Symmetric message
    Experimenter = 4,

    /* Switch configuration messages. */
    /// Controller/switch message
    FeaturesRequest = 5,
    /// Controller/switch message
    FeaturesReply = 6,
    /// Controller/switch message
    GetConfigRequest = 7,
    /// Controller/switch message
    GetConfigReply = 8,
    /// Controller/switch message
    SetConfig = 9,

    /* Asynchronous messages. */
    /// Async message
    PacketIn = 10,
    /// Async message
    FlowRemoved = 11,
    /// Async message
    PortStatus = 12,

    /* Controller command messages. */
    /// Controller/switch message
    PacketOut = 13,
    /// Controller/switch message
    FlowMod = 14,
    /// Controller/switch message
    GroupMod = 15,
    /// Controller/switch message  
    PortMod = 16,
    /// Controller/switch message
    TableMod = 17,

    /* Multipart messages. */
    /// Controller/switch message
    MultipartRequest = 18,
    /// Controller/switch message
    MultipartReply = 19,

    /* Barrier messages. */
    /// Controller/switch message
    BarrierRequest = 20,
    /// Controller/switch message
    BarrierReply = 21,

    /* Queue Configuration messages. */
    /// Controller/switch message
    QueueGetConfigRequest = 22,
    /// Controller/switch message
    QueueGetConfigReply = 23,
    /* Controller role change request messages. */
    /// Controller/switch message
    RoleRequest = 24,
    /// Controller/switch message
    RoleReply = 25,

    /* Asynchronous message configuration.  */
    /// Controller/switch message
    GetAsyncRequest = 26,
    /// Controller/switch message
    GetAsyncReply = 27,
    /// Controller/switch message
    SetAsync = 28,

    /* Meters and rate limiters configuration messages. */
    /// Controller/switch message
    MeterMod = 29,
}

#[derive(Debug)]
pub enum OfPayload {
    Hello,
    Error,
    EchoRequest,
    EchoReply,
    Experimenter,

    FeaturesRequest,
    FeaturesReply, //(features::SwitchFeatures),
    GetConfigRequest,
    GetConfigReply, //(switch_config::SwitchConfig),
    SetConfig,      //(switch_config::SwitchConfig),

    PacketIn, //(packet_in::PacketIn),
    FlowRemoved,
    PortStatus,

    PacketOut, //(packet_out::PacketOut),
    FlowMod,   //(flow_mod::FlowMod),
    GroupMod,  //(group_mod::GroupMod),
    PortMod,   //(port_mod::PortMod),
    TableMod,  //(table_mod::TableMod),

    MultipartRequest, //(multipart::MultipartRequest),
    MultipartReply,   //(multipart::MultipartReply),

    BarrierRequest,
    BarrierReply,

    QueueGetConfigRequest, //(queue_config::QueueGetConfigRequest),
    QueueGetConfigReply,   //(queue_config::QueueGetConfigReply),

    RoleRequest, //(role::Role),
    RoleReply,   //(role::Role),

    GetAsyncRequest,
    GetAsyncReply, //(async::Async),
    SetAsync,      //(async::Async),

    MeterMod, //(meter_mod::MeterMod),
}

impl OfPayload {
    pub fn generate_header(&self, xid: u32) -> Header {
        //create basic default header
        let mut header = Header {
            version: Version::V1_3,
            ttype: Type::Hello,
            length: HEADER_LENGTH as u16,
            xid: xid,
        };
        //change header depending on payload
        match self {
            OfPayload::Hello => (),
            //OfPayload::Error,
            OfPayload::EchoRequest => {
                header.ttype = Type::EchoRequest;
            }
            OfPayload::EchoReply => {
                header.ttype = Type::EchoReply;
            }
            OfPayload::Experimenter => {
                header.ttype = Type::Experimenter;
            }
            OfPayload::FeaturesRequest => {
                header.ttype = Type::FeaturesRequest;
            }
            OfPayload::FeaturesReply => {
                header.ttype = Type::FeaturesReply;
            }
            OfPayload::GetConfigRequest => {
                header.ttype = Type::GetConfigRequest;
            }
            OfPayload::GetConfigReply => {
                header.ttype = Type::GetConfigRequest;
            }
            OfPayload::SetConfig => {
                header.ttype = Type::SetConfig;
            }
            OfPayload::PacketIn => {
                header.ttype = Type::PacketIn;
            }
            OfPayload::FlowRemoved => {
                header.ttype = Type::FlowRemoved;
            }
            OfPayload::PortStatus => {
                header.ttype = Type::PortStatus;
            }
            OfPayload::PacketOut => {
                header.ttype = Type::PacketOut;
            }
            OfPayload::FlowMod => {
                header.ttype = Type::FlowMod;
            }
            OfPayload::GroupMod => {
                header.ttype = Type::GroupMod;
            }
            OfPayload::PortMod => {
                header.ttype = Type::PortMod;
            }
            OfPayload::TableMod => {
                header.ttype = Type::TableMod;
            }
            OfPayload::MultipartRequest => {
                header.ttype = Type::MultipartRequest;
            }
            OfPayload::MultipartReply => {
                header.ttype = Type::MultipartReply;
            }
            OfPayload::BarrierRequest => {
                header.ttype = Type::BarrierRequest;
            }
            OfPayload::BarrierReply => {
                header.ttype = Type::BarrierReply;
            }
            OfPayload::QueueGetConfigRequest => {
                header.ttype = Type::QueueGetConfigRequest;
            }
            OfPayload::QueueGetConfigReply => {
                header.ttype = Type::QueueGetConfigReply;
            }
            OfPayload::RoleRequest => {
                header.ttype = Type::RoleRequest;
            }
            OfPayload::RoleReply => {
                header.ttype = Type::RoleReply;
            }
            OfPayload::GetAsyncRequest => {
                header.ttype = Type::GetAsyncRequest;
            }
            OfPayload::GetAsyncReply => {
                header.ttype = Type::GetAsyncReply;
            }
            OfPayload::SetAsync => {
                header.ttype = Type::SetAsync;
            }
            OfPayload::MeterMod => {
                header.ttype = Type::MeterMod;
            }
            _ => panic!("not yet implemented header gen {:?}", self),
        }
        header
    }
}

impl Into<Vec<u8>> for OfPayload {
    fn into(self) -> Vec<u8> {
        match self {
            OfPayload::Hello => vec![],       // no body
            OfPayload::EchoRequest => vec![], // no body
            OfPayload::EchoReply => vec![],   // no body
            //OfPayload::PacketOut(payload) => payload.into(),
            _ => panic!("not yet implemented {:?}", self),
        }
    }
}
