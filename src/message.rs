use std::{io, io::Write};
use crate::message_header::MessageHeader;
use crate::message_error::MessageError;
use crate::hash::double_sha256;


#[derive(Clone, Debug)]
pub struct Message {
    header: MessageHeader,
    payload: Vec<u8>,
}

impl Message {
    pub fn from_stream<R: io::Read>(read: &mut R) -> Result<Message, MessageError> {
        let header = MessageHeader::from_stream(read)?;
        let mut payload = vec![0; header.payload_size() as usize];
        read.read_exact(&mut payload[..])?;
        let hash = double_sha256(&payload);
        if &hash[..4] != header.checksum() {
            return Err(MessageError::InvalidChecksum)
        }
        Ok(Message {
            header,
            payload,
        })
    }

    pub fn from_payload(command: &[u8], payload: Vec<u8>) -> Message {
        let hash = double_sha256(&payload);
        let mut checksum = [0; 4];
        checksum.copy_from_slice(&hash[..4]);
        let mut command_padded = [0u8; 12];
        io::Cursor::new(&mut command_padded[..]).write(command).unwrap();
        let header = MessageHeader::new(
            command_padded,
            payload.len() as u32,
            checksum,
        );
        Message {
            header,
            payload,
        }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> Result<(), MessageError> {
        self.header.write_to_stream(write)?;
        write.write(&self.payload)?;
        Ok(())
    }

    pub fn header(&self) -> &MessageHeader {
        &self.header
    }
}

impl std::fmt::Display for Message {
    fn fmt<'a>(&self, f: &mut std::fmt::Formatter<'a>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.header)?;
        writeln!(f, "payload: {}", String::from_utf8_lossy(&self.payload))?;
        Ok(())
    }
}
