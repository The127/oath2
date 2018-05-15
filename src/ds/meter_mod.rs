use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{TryFrom, Into};
use std::io::{Cursor};

use super::super::err::*;

#[derive(Debug)]
pub struct MeterMod {
    pub command: MeterModCommand,
    pub flags: MeterFlags,
    pub meter_id: u32,
    pub bands: Vec<MeterBandPayload>,
}

unsafe impl Send for MeterMod {}

impl Into<Vec<u8>> for MeterMod {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        //pad 4 bytes
        res.write_u16::<BigEndian>(self.command.to_u16().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.flags.bits()).unwrap();
        res.write_u32::<BigEndian>(self.meter_id).unwrap();
        for band in self.bands{
            res.extend_from_slice(&Into::<Vec<u8>>::into(band)[..]);
        }
        res
    }
}

/// Meter commands 
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum MeterModCommand {
    /// New meter. 
    Add = 1, 
    /// Modify specified meter. 
    Modify = 2,
    /// Delete specified meter. 
    Delete = 3, 
}

unsafe impl Send for MeterModCommand {}

/* Meter configuration flags */
bitflags!{
    pub struct MeterFlags: u16 {
        /// Rate value in kb/s (kilo-bit per second). 
        const KBPS = 1 << 0; 
        /// Rate value in packet/sec. 
        const PKTPS = 1 << 1; 
        /// Do burst size. 
        const BURST = 1 << 2; 
        /// Collect statistics. 
        const STATS = 1 << 3;
    }
}

unsafe impl Send for MeterFlags {}

/// Common header for all meter bands 
#[derive(Debug)]
pub struct MeterBandHeader {
    /// One of OFPMBT_*. 
    ttype: MeterBandType, 
    /// Length in bytes of this band. 
    len: u16, 
    /// Rate for this band. 
    rate: u32,
    /// Size of bursts. 
    burst_size: u32, 
    payload: MeterBandPayload,
}

unsafe impl Send for MeterBandHeader {}

impl Into<Vec<u8>> for MeterBandHeader {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ttype.to_u16().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.write_u32::<BigEndian>(self.rate).unwrap();
        res.write_u32::<BigEndian>(self.burst_size).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.payload)[..]);
        res
    }
}

impl<'a> TryFrom<&'a [u8]> for MeterBandHeader {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let ttype_raw = cursor.read_u16::<BigEndian>().unwrap();
        let ttype = MeterBandType::from_u16(ttype_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(ttype_raw as u64, stringify!(MeterBandType)).into())?;
        let len = cursor.read_u16::<BigEndian>().unwrap();
        let rate = cursor.read_u32::<BigEndian>().unwrap();
        let burst_size = cursor.read_u32::<BigEndian>().unwrap();

        let payload_slice = &bytes[12..];
        let payload = match ttype {
            MeterBandType::Drop => MeterBandPayload::Drop(MeterBandDrop::try_from(payload_slice)?),
            MeterBandType::DscpRemark => MeterBandPayload::Remark(MeterBandRemark::try_from(payload_slice)?),
            MeterBandType::Experimenter => MeterBandPayload::Experimenter(MeterBandExperimenter::try_from(payload_slice)?),
        };
        Ok(MeterBandHeader{
            ttype: ttype,
            len: len,
            rate: rate,
            burst_size: burst_size,
            payload: payload,
        })
    }
}

/// Meter band types 
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum MeterBandType {
    /// Drop packet. 
    Drop = 1, 
    /// Remark DSCP in the IP header. 
    DscpRemark = 2, 
    /// Experimenter meter band. 
    Experimenter = 0xFFFF,
}

#[derive(Debug, PartialEq, Clone)]
pub enum MeterBandPayload {
    Drop(MeterBandDrop),
    Remark(MeterBandRemark),
    Experimenter(MeterBandExperimenter),
}

unsafe impl Send for MeterBandPayload {}

impl Into<Vec<u8>> for MeterBandPayload {
    fn into(self) -> Vec<u8> {
        match self {
            MeterBandPayload::Drop(payload) => payload.into(),
            MeterBandPayload::Remark(payload) => payload.into(),
            MeterBandPayload::Experimenter(payload) => payload.into(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MeterBandDrop {
    //pad 4 bytes
}

unsafe impl Send for MeterBandDrop {}

impl Into<Vec<u8>> for MeterBandDrop {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        //pad 4 bytes
        res.write_u32::<BigEndian>(0).unwrap();
        res
    }
}

impl<'a> TryFrom<&'a [u8]> for MeterBandDrop {
    type Error = Error;
    fn try_from(_bytes: &'a [u8]) -> Result<Self> {
        // pad by ignoring
        Ok(MeterBandDrop{
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MeterBandRemark {
    prec_level: u8,
    //pad 3 bytes
}

unsafe impl Send for MeterBandRemark {}

impl Into<Vec<u8>> for MeterBandRemark {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.prec_level).unwrap();
        //pad 3 bytes
        res.write_u8(0).unwrap();
        res.write_u8(0).unwrap();
        res.write_u8(0).unwrap();
        res
    }
}

impl<'a> TryFrom<&'a [u8]> for MeterBandRemark {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let prec_level = cursor.read_u8().unwrap();
        // pad by ignoring
        Ok(MeterBandRemark{
            prec_level: prec_level,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MeterBandExperimenter {
    experimenter: u32,
}

unsafe impl Send for MeterBandExperimenter {}

impl Into<Vec<u8>> for MeterBandExperimenter {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.experimenter).unwrap();
        res
    }
}

impl<'a> TryFrom<&'a [u8]> for MeterBandExperimenter {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let experimenter = cursor.read_u32::<BigEndian>().unwrap();
        Ok(MeterBandExperimenter{
            experimenter: experimenter,
        })
    }
}
