use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::flow_instructions;
use super::flow_match::Match;
use super::ports::PortNumber;

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct FlowMod {
    pub cookie: u64,
    pub cookie_mask: u64,
    pub table_id: u8,
    pub command: FlowModCommand,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub priority: u16,
    pub buffer_id: u32,
    pub out_port: PortNumber,
    pub out_group: u32,
    pub flags: FlowModFlags,
    //pad 2 bytes
    pub mmatch: Match,
    pub instructions: Vec<flow_instructions::InstructionHeader>,
}

unsafe impl Send for FlowMod {}

impl<'a> TryFrom<&'a [u8]> for FlowMod {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let cookie = cursor.read_u64::<BigEndian>().unwrap();
        let cookie_mask = cursor.read_u64::<BigEndian>().unwrap();
        let table_id = cursor.read_u8().unwrap();
        let command_raw = cursor.read_u8().unwrap();
        let command = FlowModCommand::from_u8(command_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(command_raw as u64, stringify!(FlowModCommand)).into(),
        )?;
        let idle_timeout = cursor.read_u16::<BigEndian>().unwrap();
        let hard_timeout = cursor.read_u16::<BigEndian>().unwrap();
        let priority = cursor.read_u16::<BigEndian>().unwrap();
        let buffer_id = cursor.read_u32::<BigEndian>().unwrap();
        let out_port = PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?;
        let out_group = cursor.read_u32::<BigEndian>().unwrap();
        let flags_raw = cursor.read_u16::<BigEndian>().unwrap();
        let flags = FlowModFlags::from_bits(flags_raw).unwrap();

        let mmatch_slice_len = Match::read_len(&mut cursor)?;
        let mmatch_slice =
            &bytes[cursor.position() as usize..cursor.position() as usize + mmatch_slice_len];

        let mmatch = Match::try_from(mmatch_slice)?;
        cursor
            .seek(SeekFrom::Current(mmatch_slice_len as i64))
            .unwrap();

        let mut instructions = Vec::new();
        let mut bytes_left = bytes.len() as u64;
        while bytes_left > cursor.position() {
            let instruction_len = flow_instructions::get_instruction_slice_len(&mut cursor);
            let instruction_slice =
                &bytes[cursor.position() as usize..cursor.position() as usize + instruction_len];
            let instruction = flow_instructions::InstructionHeader::try_from(instruction_slice)?;
            cursor
                .seek(SeekFrom::Current(instruction_len as i64))
                .unwrap();
            bytes_left -= instruction_len as u64;
            instructions.push(instruction);
        }

        Ok(FlowMod {
            cookie: cookie,
            cookie_mask: cookie_mask,
            table_id: table_id,
            command: command,
            idle_timeout: idle_timeout,
            hard_timeout: hard_timeout,
            priority: priority,
            buffer_id: buffer_id,
            out_port: out_port,
            out_group: out_group,
            flags: flags,
            mmatch: mmatch,
            instructions: instructions,
        })
    }
}

impl Into<Vec<u8>> for FlowMod {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u64::<BigEndian>(self.cookie).unwrap();
        res.write_u64::<BigEndian>(self.cookie_mask).unwrap();
        res.write_u8(self.table_id).unwrap();
        res.write_u8(self.command.to_u8().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.idle_timeout).unwrap();
        res.write_u16::<BigEndian>(self.hard_timeout).unwrap();
        res.write_u16::<BigEndian>(self.priority).unwrap();
        res.write_u32::<BigEndian>(self.buffer_id).unwrap();
        res.write_u32::<BigEndian>(self.out_port.into()).unwrap();
        res.write_u32::<BigEndian>(self.out_group).unwrap();
        res.write_u16::<BigEndian>(self.flags.bits()).unwrap();
        res.write_u16::<BigEndian>(0).unwrap(); // pad 2 bytes
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.mmatch)[..]);
        for instruction in self.instructions {
            res.extend_from_slice(&Into::<Vec<u8>>::into(instruction)[..]);
        }
        res
    }
}

#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum FlowModCommand {
    ///  New flow.
    Add = 0,
    /// Modify all matching flows.
    Modify = 1,
    ///  Modify entry strictly matching wildcards and
    /// priority.
    ModifyStrict = 2,
    /// /// Delete all matching flows.
    Delete = 3,
    /// Delete entry strictly matching wildcards and
    /// priority.
    DeleteStrict = 4,
}

bitflags!{
    pub struct FlowModFlags: u16 {
        /// Send flow removed message when flow
        // expires or is deleted.
        const SEND_FLOW_REM = 1 << 0;
        /// Check for overlapping entries first.
        const CHECK_OVERLAP = 1 << 1;
        /// Reset flow packet and byte counts.
        const RESET_COUNTS = 1 << 2;
        /// Don't keep track of packet count.
        const NO_PKT_COUNTS = 1 << 3;
        /// Don't keep track of byte count.
        const NO_BYT_COUNTS = 1 << 4;
    }
}
