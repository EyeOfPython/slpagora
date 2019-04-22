use std::io;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};


pub fn write_var_int<W: io::Write>(write: &mut W, number: u64) -> io::Result<()> {
    match number {
        0 ... 0xfc        => write.write_u8(number as u8)?,
        0 ... 0xffff      => {
            write.write(b"\xfd")?;
            write.write_u16::<LittleEndian>(number as u16)?
        },
        0 ... 0xffff_ffff => {
            write.write(b"\xfe")?;
            write.write_u32::<LittleEndian>(number as u32)?
        },
        _                 => {
            write.write(b"\xff")?;
            write.write_u64::<LittleEndian>(number as u64)?
        },
    }
    Ok(())
}

pub fn write_var_str<W: io::Write>(write: &mut W, string: &[u8]) -> io::Result<()> {
    write_var_int(write, string.len() as u64)?;
    write.write(string)?;
    Ok(())
}

pub fn read_var_int<R: io::Read>(read: &mut R) -> io::Result<u64> {
    let first_byte = read.read_u8()?;
    match first_byte {
        0 ... 0xfc => Ok(first_byte as u64),
        0xfd       => Ok(read.read_u16::<LittleEndian>()? as u64),
        0xfe       => Ok(read.read_u32::<LittleEndian>()? as u64),
        0xff       => Ok(read.read_u64::<LittleEndian>()? as u64),
    }
}

pub fn read_var_str<R: io::Read>(read: &mut R) -> io::Result<Vec<u8>> {
    let mut vec = vec![0; read_var_int(read)? as usize];
    read.read_exact(&mut vec)?;
    Ok(vec)
}
