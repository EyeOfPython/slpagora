use std::io;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};


#[derive(Clone, Debug)]
pub enum Op {
    PUSH(Vec<u8>),
    RETURN,
    DUP,
    EQUAL,
    EQUALVERIFY,
    HASH160,
    CHECKSIG,
    CHECKSIGVERIFY,
}

impl Op {
    pub fn code(&self) -> u8 {
        match self {
            Op::PUSH(vec) => {
                match vec.len() {
                    0 ... 0x4b        => vec.len() as u8,
                    0 ... 0xff        => 0x4c,
                    0 ... 0xffff      => 0x4d,
                    0 ... 0xffff_ffff => 0x4e,
                    _                 => unimplemented!(),
                }
            },
            Op::RETURN => 0x6a,
            Op::DUP => 0x76,
            Op::EQUAL => 0x87,
            Op::EQUALVERIFY => 0x88,
            Op::HASH160 => 0xa9,
            Op::CHECKSIG => 0xac,
            Op::CHECKSIGVERIFY => 0xad,
        }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_u8(self.code())?;
        if let Op::PUSH(vec) = self {
            match vec.len() {
                0 ... 0x4b => {},
                len @ (0 ... 0xff) => { write.write_u8(len as u8)? },
                len @ (0 ... 0xffff) => { write.write_u16::<LittleEndian>(len as u16)? },
                len @ (0 ... 0xffff_ffff) => { write.write_u32::<LittleEndian>(len as u32)? },
                _ => {},
            };
            write.write(vec)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Script {
    ops: Vec<Op>,
}

impl Script {
    pub fn empty() -> Self {
        Script { ops: vec![] }
    }

    pub fn new(ops: Vec<Op>) -> Self {
        Script { ops }
    }

    pub fn from_serialized(data: &[u8]) -> Self {
        let mut ops = Vec::new();
        let mut idx = 0;
        while idx < data.len() {
            match data[idx] {
                n_bytes @ (0 ... 0x4b) => {
                    let n_bytes = n_bytes as usize;
                    ops.push(Op::PUSH(data[idx + 1..idx + 1 + n_bytes].to_vec()));
                    idx += n_bytes;
                },
                0x4c => {
                    let n_bytes = data[idx + 1] as usize;
                    ops.push(Op::PUSH(data[idx + 1..idx + 1 + n_bytes].to_vec()));
                    idx += n_bytes;
                },
                0x4d => unimplemented!(),
                0x4e => unimplemented!(),
                0x6a => ops.push(Op::RETURN),
                0x76 => ops.push(Op::DUP),
                0x87 => ops.push(Op::EQUAL),
                0x88 => ops.push(Op::EQUALVERIFY),
                0xa9 => ops.push(Op::HASH160),
                0xac => ops.push(Op::CHECKSIG),
                0xad => ops.push(Op::CHECKSIGVERIFY),
                _ => unimplemented!(),
            }
            idx += 1;
        }
        Script { ops }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        for op in self.ops.iter() {
            op.write_to_stream(&mut vec).unwrap();
        }
        vec
    }
}
