
use super::super::err::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{TryFrom, Into};
use std::io::{SeekFrom, Seek, Cursor};

use std::path;

#[derive(Primitive, Debug, PartialEq, Clone)]
pub enum InstructionType {
    /// Setup the next table in the lookup pipeline 
    GotoTable = 1, 
    /// Setup the metadata field for use later in pipeline 
    WriteMetadata = 2, 
    /// Write the action(s) onto the datapath action set 
    WriteActions = 3, 
    /// Applies the action(s) immediately 
    ApplyActions = 4, 
    /// Clears all actions from the datapath
    /// action set 
    Clearactions = 5, 
    /// Apply meter (rate limiter) 
    Meter = 6, 
    /// Experimenter instruction 
    Experimenter = 0xFFFF, 
}

#[derive(Debug, PartialEq, Clone)]
pub struct InstructionHeader {
    /// OFPIT_GOTO_TABLE 
    ttype: InstructionType, 
    /// Length of this struct in bytes. 
    len: u16, 
    payload: InstructionPayload,
}

pub fn get_instruction_slice_len(cur: &mut Cursor<&[u8]>) -> usize {
    cur.seek(SeekFrom::Current(2)).unwrap();//skip to length
    let len = cur.read_u16::<BigEndian>().unwrap();
    cur.seek(SeekFrom::Current(-4)).unwrap();
    len as usize
}

impl Into<Vec<u8>> for InstructionHeader {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ttype.to_u16().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.payload));
        res
    }
}

impl<'a> TryFrom<&'a [u8]> for InstructionHeader {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);

        let raw_ttype = cursor.read_u16::<BigEndian>().chain_err(|| {
            let err_msg = format!(
                "Could not read InstructionHeader raw_ttype!{}Cursor: {:?}",
                path::MAIN_SEPARATOR,
                cursor
            );
            error!("{}", err_msg);
            err_msg
        })?;
        let ttype = InstructionType::from_u16(raw_ttype)
            .ok_or::<Error>(ErrorKind::UnknownValue(raw_ttype as u64, stringify!(InstructionType)).into())?;

        let length = cursor.read_u16::<BigEndian>().chain_err(|| {
            let err_msg = format!(
                "Could not read InstructionHeader length!{}Cursor: {:?}",
                path::MAIN_SEPARATOR,
                cursor
            );
            error!("{}", err_msg);
            err_msg
        })?;
        let payload_slice = &bytes[4..];

        let payload = match ttype {
            InstructionType::GotoTable => InstructionPayload::GotoTable(PayloadGotoTable::try_from(payload_slice)?),
            InstructionType::WriteMetadata => InstructionPayload::WriteMetaData(PayloadWriteMetaData::try_from(payload_slice)?),
            InstructionType::WriteActions => InstructionPayload::WriteActions(PayloadWriteActions::try_from(payload_slice)?),
            InstructionType::ApplyActions => InstructionPayload::ApplyActions(PayloadApplyActions::try_from(payload_slice)?),
            InstructionType::Clearactions => InstructionPayload::ClearActions(PayloadClearActions::try_from(payload_slice)?),
            InstructionType::Meter => InstructionPayload::Meter(PayloadMeter::try_from(payload_slice)?),
            InstructionType::Experimenter => bail!(ErrorKind::UnsupportedValue(
                ttype as u64,
                stringify!(InstructionType),
            )),
        };

        Ok(InstructionHeader{
            ttype: ttype,
            len: length,
            payload: payload,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum InstructionPayload{
    GotoTable(PayloadGotoTable),
    WriteMetaData(PayloadWriteMetaData),
    WriteActions(PayloadWriteActions),
    ApplyActions(PayloadApplyActions),
    ClearActions(PayloadClearActions),
    Meter(PayloadMeter),
    //Experimenter(PayloadExperimenter), // not supported
}

impl Into<Vec<u8>> for InstructionPayload {
    fn into(self) -> Vec<u8> {
        match self {
            InstructionPayload::GotoTable(payload) => payload.into(),
            InstructionPayload::WriteMetaData(payload) => payload.into(),
            InstructionPayload::WriteActions(payload) => payload.into(),
            InstructionPayload::ApplyActions(payload) => payload.into(),
            InstructionPayload::ClearActions(payload) => payload.into(),
            InstructionPayload::Meter(payload) => payload.into(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadGotoTable {
    /// Set next table in the lookup pipeline 
    table_id: u8, 
    // Pad 3 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadGotoTable {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadGotoTable{
            table_id: cursor.read_u8().chain_err(|| {
                let err_msg = format!(
                    "Could not read PayloadGotoTable table_id!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
        })
        // pad 3 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for PayloadGotoTable {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.table_id).unwrap();
        res.write_u8(0).unwrap(); // pad 1 byte
        res.write_u16::<BigEndian>(0).unwrap(); // pad 2 bytes
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadWriteMetaData {
    // pad 4 bytes
    metadata: u64,
    metadata_mask: u64,
}

impl<'a> TryFrom<&'a [u8]> for PayloadWriteMetaData {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.read_u32::<BigEndian>().unwrap(); //4 bytes padding
        Ok(PayloadWriteMetaData{
            metadata: cursor.read_u64::<BigEndian>().chain_err(|| {
                let err_msg = format!(
                    "Could not read PayloadWriteMetaData metadata!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
            metadata_mask: cursor.read_u64::<BigEndian>().chain_err(|| {
                let err_msg = format!(
                    "Could not read PayloadWriteMetaData metadata_mask!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
        })
    }
}

impl Into<Vec<u8>> for PayloadWriteMetaData {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        res.write_u64::<BigEndian>(self.metadata).unwrap(); // pad 4 bytes
        res.write_u64::<BigEndian>(self.metadata_mask).unwrap(); // pad 4 bytes
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadWriteActions {
    // pad 4 bytes
    actions: Vec<()>,
}

impl<'a> TryFrom<&'a [u8]> for PayloadWriteActions {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        //TODO
        unimplemented!()
    }
}

impl Into<Vec<u8>> for PayloadWriteActions {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        for action in self.actions {
            //TODO
            unimplemented!()
        }
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadApplyActions {
    // pad 4 bytes
    actions: Vec<()>,
}
impl<'a> TryFrom<&'a [u8]> for PayloadApplyActions {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        //TODO
        unimplemented!()
    }
}

impl Into<Vec<u8>> for PayloadApplyActions {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        for action in self.actions {
            //TODO
            unimplemented!()
        }
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadClearActions {
    //pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for PayloadClearActions {
    type Error = Error ;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadClearActions{})
    }
}

impl Into<Vec<u8>> for PayloadClearActions {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadMeter {
    meter_id: u32,
}

impl<'a> TryFrom<&'a [u8]> for PayloadMeter {
    type Error = Error ;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadMeter{
            meter_id: cursor.read_u32::<BigEndian>().chain_err(|| {
                let err_msg = format!(
                    "Could not read PayloadMeter meter_id!{}Cursor: {:?}",
                    path::MAIN_SEPARATOR,
                    cursor
                );
                error!("{}", err_msg);
                err_msg
            })?,
        })
    }
}

impl Into<Vec<u8>> for PayloadMeter {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.meter_id).unwrap(); // pad 4 bytes
        res
    }
}
