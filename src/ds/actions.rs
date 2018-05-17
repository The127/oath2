use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::super::err::*;
use super::flow_match::*;
use super::ports::PortNumber;

use std::path;

#[derive(Primitive, Debug, PartialEq, Clone)]
pub enum ActionType {
    /// Output to switch port.
    Output = 0,
    /// Copy TTL "outwards" -- from next-to-outermost to outermost
    CopyTtlOut = 11,
    /// Copy TTL "inwards" -- from outermost to next-to-outermost
    CopyTtlIn = 12,
    /// MPLS TTL
    SetMplsTtl = 15,
    /// Decrement MPLS TTL
    DecMplsTtl = 16,
    /// Push a new VLAN tag
    PushVlan = 17,
    /// Pop the outer VLAN tag
    PopVlan = 18,
    /// Push a new MPLS tag
    PushMpls = 19,
    /// Pop the outer MPLS tag
    PopMpls = 20, /* */
    /// Set queue id when outputting to a port
    SetQueue = 21,
    /// Apply group.
    Group = 22, /* . */
    /// IP TTL.
    SetNwTtl = 23,
    /// Decrement IP TTL.
    DecNwTtl = 24,
    /// Set a header field using OXM TLV format.
    SetField = 25,
    /// Push a new PBB service tag (I-TAG)
    PushPbb = 26,
    /// Pop the outer PBB service tag (I-TAG)
    PopPbb = 27,
    // not supported
    //Experimenter = 0xffff,
}

pub fn calc_actions_len(actions: &Vec<ActionHeader>) -> u16 {
    let mut actions_len = 0;
    for action in actions {
        actions_len += action.len();
    }
    actions_len
}

pub const ACTION_HEADER_LEN: u16 = 4;

#[derive(Getters, Debug, PartialEq, Clone)]
pub struct ActionHeader {
    ttype: ActionType,
    #[get = "pub"]
    len: u16,
    payload: ActionPayload,
}

impl ActionHeader {
    pub fn read_len(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
        // go to len position in the raw bytes
        cursor.seek(SeekFrom::Current(2)).unwrap();
        // read value and handle errors
        let len = match cursor.read_u16::<BigEndian>() {
            Ok(len) => len,
            Err(err) => {
                error!(
                    "Could not read packet queue len.{}{:?}{}{}",
                    path::MAIN_SEPARATOR,
                    cursor,
                    path::MAIN_SEPARATOR,
                    err
                );
                bail!(ErrorKind::CouldNotReadLength(2, stringify!(PacketQueue),))
            }
        };
        // go back to start
        cursor.seek(SeekFrom::Current(-4)).unwrap();
        Ok(len as usize)
    }
}

impl<'a> TryFrom<&'a [u8]> for ActionHeader {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ttype = cursor.read_u16::<BigEndian>().unwrap();
        let ttype = ActionType::from_u16(raw_ttype).ok_or::<Error>(
            ErrorKind::UnknownValue(raw_ttype as u64, stringify!(ActionType)).into(),
        )?;
        let len = cursor.read_u16::<BigEndian>().unwrap();
        let payload = try_from_action_payload(&bytes[4..], &ttype)?;
        Ok(ActionHeader {
            ttype: ttype,
            len: len,
            payload: payload,
        })
    }
}

impl Into<Vec<u8>> for ActionHeader {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ttype.to_u16().unwrap())
            .unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.payload)[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ActionPayload {
    Output(PayloadOutput),
    CopyTtlOut(PayloadCopyTtlOut),
    CopyTtlIn(PayloadCopyTtlIn),
    SetMplsTtl(PayloadSetMplsTtl),
    DecMplsTtl(PayloadDecMplsTtl),
    PushVlan(PayloadPushVlan),
    PopVlan(PayloadPopVlan),
    PushMpls(PayloadPushMpls),
    PopMpls(PayloadPopMpls),
    SetQueue(PayloadSetQueue),
    Group(PayloadGroup),
    SetNwTtl(PayloadSetNwTtl),
    DecNwTtl(PayloadDecNwTtl),
    SetField(PayloadSetField),
    PushPbb(PayloadPushPbb),
    PopPbb(PayloadPopPbb),
    //Experimenter(PayloadExperimenter),
}

impl Into<Vec<u8>> for ActionPayload {
    fn into(self) -> Vec<u8> {
        match self {
            ActionPayload::Output(payload) => payload.into(),
            ActionPayload::CopyTtlOut(payload) => payload.into(),
            ActionPayload::CopyTtlIn(payload) => payload.into(),
            ActionPayload::SetMplsTtl(payload) => payload.into(),
            ActionPayload::DecMplsTtl(payload) => payload.into(),
            ActionPayload::PushVlan(payload) => payload.into(),
            ActionPayload::PopVlan(payload) => payload.into(),
            ActionPayload::PushMpls(payload) => payload.into(),
            ActionPayload::PopMpls(payload) => payload.into(),
            ActionPayload::SetQueue(payload) => payload.into(),
            ActionPayload::Group(payload) => payload.into(),
            ActionPayload::SetNwTtl(payload) => payload.into(),
            ActionPayload::DecNwTtl(payload) => payload.into(),
            ActionPayload::SetField(payload) => payload.into(),
            ActionPayload::PushPbb(payload) => payload.into(),
            ActionPayload::PopPbb(payload) => payload.into(),
        }
    }
}

fn try_from_action_payload(bytes: &[u8], ttype: &ActionType) -> Result<ActionPayload> {
    Ok(match ttype {
        ActionType::Output => ActionPayload::Output(PayloadOutput::try_from(bytes)?),
        ActionType::CopyTtlOut => ActionPayload::CopyTtlOut(PayloadCopyTtlOut::try_from(bytes)?),
        ActionType::CopyTtlIn => ActionPayload::CopyTtlIn(PayloadCopyTtlIn::try_from(bytes)?),
        ActionType::SetMplsTtl => ActionPayload::SetMplsTtl(PayloadSetMplsTtl::try_from(bytes)?),
        ActionType::DecMplsTtl => ActionPayload::DecMplsTtl(PayloadDecMplsTtl::try_from(bytes)?),
        ActionType::PushVlan => ActionPayload::PushVlan(PayloadPushVlan::try_from(bytes)?),
        ActionType::PopVlan => ActionPayload::PopVlan(PayloadPopVlan::try_from(bytes)?),
        ActionType::PushMpls => ActionPayload::PushMpls(PayloadPushMpls::try_from(bytes)?),
        ActionType::PopMpls => ActionPayload::PopMpls(PayloadPopMpls::try_from(bytes)?),
        ActionType::SetQueue => ActionPayload::SetQueue(PayloadSetQueue::try_from(bytes)?),
        ActionType::Group => ActionPayload::Group(PayloadGroup::try_from(bytes)?),
        ActionType::SetNwTtl => ActionPayload::SetNwTtl(PayloadSetNwTtl::try_from(bytes)?),
        ActionType::DecNwTtl => ActionPayload::DecNwTtl(PayloadDecNwTtl::try_from(bytes)?),
        ActionType::SetField => ActionPayload::SetField(PayloadSetField::try_from(bytes)?),
        ActionType::PushPbb => ActionPayload::PushPbb(PayloadPushPbb::try_from(bytes)?),
        ActionType::PopPbb => ActionPayload::PopPbb(PayloadPopPbb::try_from(bytes)?),
    })
}

pub const PAYLOAD_OUTPUT_LEN: u16 = 12;

/// Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
/// When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
/// number of bytes to send. A 'max_len' of zero means no bytes of the
/// packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
/// the packet is not buffered and the complete packet is to be sent to
/// the controller.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadOutput {
    pub port: PortNumber,
    pub max_len: u16,
    // pad 6 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadOutput {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_port = cursor.read_u32::<BigEndian>().unwrap();
        let port = PortNumber::try_from(raw_port)?;
        Ok(PayloadOutput {
            port: port,
            max_len: cursor.read_u16::<BigEndian>().unwrap(),
        })
        //pad 6 bytes by ignoring them
    }
}

impl Into<ActionHeader> for PayloadOutput {
    fn into(self) -> ActionHeader {
        ActionHeader {
            ttype: ActionType::Output,
            len: ACTION_HEADER_LEN + PAYLOAD_OUTPUT_LEN,
            payload: ActionPayload::Output(self),
        }
    }
}

impl Into<Vec<u8>> for PayloadOutput {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.port.into()).unwrap();
        res.write_u16::<BigEndian>(self.max_len).unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadGroup {
    group_id: u32,
}

impl<'a> TryFrom<&'a [u8]> for PayloadGroup {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadGroup {
            group_id: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadGroup {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.group_id).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSetQueue {
    queue_id: u32,
}

impl<'a> TryFrom<&'a [u8]> for PayloadSetQueue {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadSetQueue {
            queue_id: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadSetQueue {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.queue_id).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSetMplsTtl {
    mpls_ttl: u8,
    // pad 3 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadSetMplsTtl {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadSetMplsTtl {
            mpls_ttl: cursor.read_u8().unwrap(),
        })
        // pad 3 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadSetMplsTtl {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.mpls_ttl).unwrap();
        res.write_u8(0).unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadDecMplsTtl {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadDecMplsTtl {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadDecMplsTtl {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadDecMplsTtl {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSetNwTtl {
    nw_ttl: u8,
    // pad 3 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadSetNwTtl {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadSetNwTtl {
            nw_ttl: cursor.read_u8().unwrap(),
        })
        // pad 3 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadSetNwTtl {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.nw_ttl).unwrap();
        res.write_u8(0).unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadDecNwTtl {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadDecNwTtl {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadDecNwTtl {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadDecNwTtl {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadCopyTtlOut {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadCopyTtlOut {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadCopyTtlOut {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadCopyTtlOut {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadCopyTtlIn {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadCopyTtlIn {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadCopyTtlIn {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadCopyTtlIn {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPushVlan {
    ethertype: EtherType,
    // pad 2 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPushVlan {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ethertpye = cursor.read_u16::<BigEndian>().unwrap();
        let ethertype = EtherType::from_u16(raw_ethertpye).ok_or::<Error>(
            ErrorKind::UnknownValue(raw_ethertpye as u64, stringify!(EtherType)).into(),
        )?;
        Ok(PayloadPushVlan {
            ethertype: ethertype,
        })
        // pad 2 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPushVlan {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ethertype.to_u16().unwrap())
            .unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPushMpls {
    ethertype: EtherType,
    // pad 2 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPushMpls {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ethertpye = cursor.read_u16::<BigEndian>().unwrap();
        let ethertype = EtherType::from_u16(raw_ethertpye).ok_or::<Error>(
            ErrorKind::UnknownValue(raw_ethertpye as u64, stringify!(EtherType)).into(),
        )?;
        Ok(PayloadPushMpls {
            ethertype: ethertype,
        })
        // pad 2 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPushMpls {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ethertype.to_u16().unwrap())
            .unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPushPbb {
    ethertype: EtherType,
    // pad 2 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPushPbb {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ethertpye = cursor.read_u16::<BigEndian>().unwrap();
        let ethertype = EtherType::from_u16(raw_ethertpye).ok_or::<Error>(
            ErrorKind::UnknownValue(raw_ethertpye as u64, stringify!(EtherType)).into(),
        )?;
        Ok(PayloadPushPbb {
            ethertype: ethertype,
        })
        // pad 2 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPushPbb {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ethertype.to_u16().unwrap())
            .unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPopVlan {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPopVlan {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadPopVlan {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPopVlan {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPopMpls {
    ethertype: EtherType,
    // pad 2 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPopMpls {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ethertpye = cursor.read_u16::<BigEndian>().unwrap();
        let ethertype = EtherType::from_u16(raw_ethertpye).ok_or::<Error>(
            ErrorKind::UnknownValue(raw_ethertpye as u64, stringify!(EtherType)).into(),
        )?;
        Ok(PayloadPopMpls {
            ethertype: ethertype,
        })
        // pad 2 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPopMpls {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ethertype.to_u16().unwrap())
            .unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPopPbb {
    // pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadPopPbb {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadPopPbb {})
        // pad 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadPopPbb {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

/// Action structure for OFPAT_GROUP.
#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSetField {
    // pad 4 bytes
    field: TlvMatch,
    /* Followed by:
     * - Exactly (length - 4) (possibly 0) bytes containing OXM TLVs, then
     * - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     * all-zero bytes
     * In summary, ofp_match is padded as needed, to make its overall size
     * a multiple of 8, to preserve alignement in structures using it.
     */
}

impl<'a> TryFrom<&'a [u8]> for PayloadSetField {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let tlv_header = OxmTlvHeader(cursor.read_u32::<BigEndian>().unwrap());
        let field = TlvMatch::try_from(tlv_header, &bytes[4..])?;
        Ok(PayloadSetField { field: field })
        // pad n bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadSetField {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        let len = self.field.tlv_header.get_length() + 4; //add 4 bytes from msg header
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.field)[..]);
        let pad_bytes_count = (len + 7) / 8 * 8 - len;
        for _ in 0..pad_bytes_count {
            res.write_u8(0).unwrap();
        }
        res
    }
}
