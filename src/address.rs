const CHARSET: &'static [u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const DEFAULT_PREFIX: &'static str = "bitcoincash";

#[derive(Clone, Debug)]
pub enum AddressError {
    InvalidChecksum,
    InvalidBase32Letter(usize, u8),
    InvalidAddressType(u8),
}

#[derive(Clone, Copy, Debug)]
pub enum AddressType {
    P2PKH = 0,
    P2SH = 8,
}

fn convert_bits(data: impl Iterator<Item=u8>, from_bits: u32, to_bits: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc = 0;
    let mut bits = 0;
    let mut ret = Vec::new();
    let maxv = (1 << to_bits) - 1;
    let max_acc = (1 << (from_bits + to_bits - 1)) - 1;
    for value in data {
        let value = value as u32;
        if (value >> from_bits) != 0 {
            return None
        }
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits != 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv != 0) {
        return None
    }
    Some(ret)
}

fn poly_mod(values: impl Iterator<Item=u8>) -> u64 {
    let mut c = 1;
    for value in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07ffffffffu64) << 5u64) ^ (value as u64);
        if c0 & 0x01 != 0 { c ^= 0x98f2bc8e61 }
        if c0 & 0x02 != 0 { c ^= 0x79b76d99e2 }
        if c0 & 0x04 != 0 { c ^= 0xf33e5fb3c4 }
        if c0 & 0x08 != 0 { c ^= 0xae2eabe2a8 }
        if c0 & 0x10 != 0 { c ^= 0x1e4f43e470 }
    }
    c ^ 1
}

fn calculate_checksum(prefix: &str, payload: impl Iterator<Item=u8>) -> Vec<u8> {
    let poly = poly_mod(
        prefix.as_bytes().iter()
            .map(|x| *x & 0x1f)
            .chain([0].iter().cloned())
            .chain(payload)
            .chain([0, 0, 0, 0, 0, 0, 0, 0].iter().cloned())
    );
    (0..8).into_iter()
        .map(|i| ((poly >> 5 * (7 - i)) & 0x1f) as u8)
        .collect()
}

fn verify_checksum(prefix: &str, payload: impl Iterator<Item=u8>) -> bool {
    let poly = poly_mod(
        prefix.as_bytes().iter()
            .map(|x| *x & 0x1f)
            .chain([0].iter().cloned())
            .chain(payload)
    );
    poly == 0
}

fn b32_encode(data: impl Iterator<Item=u8>) -> String {
    String::from_utf8(data.map(|x| CHARSET[x as usize]).collect()).unwrap()
}

fn b32_decode(string: &str) -> Result<Vec<u8>, AddressError> {
    string.as_bytes().iter()
        .enumerate()
        .map(|(i, x)|
            CHARSET.iter()
                .position(|c| x == c)
                .map(|x| x as u8)
                .ok_or(AddressError::InvalidBase32Letter(i, *x))
        )
        .collect()
}

pub fn to_cash_addr(prefix: &str, addr_type: AddressType, addr_bytes: &[u8; 20]) -> String {
    let version = addr_type as u8;
    let payload = convert_bits(
        [version].iter().chain(addr_bytes.iter()).cloned(),
        8,
        5,
        true,
    ).unwrap();
    let checksum = calculate_checksum(prefix, payload.iter().cloned());
    String::from(prefix) + ":" + &b32_encode(payload.iter().cloned().chain(checksum.iter().cloned()))
}

pub fn from_cash_addr(addr_string: &str) -> Result<([u8; 20], AddressType, String), AddressError> {
    let addr_string = addr_string.to_ascii_lowercase();
    let (prefix, payload_base32) = if let Some(pos) = addr_string.find(":") {
        let (prefix, payload_base32) = addr_string.split_at(pos + 1);
        (&prefix[..prefix.len() - 1], payload_base32)
    } else {
        (&addr_string[..], DEFAULT_PREFIX)
    };
    let decoded = b32_decode(payload_base32)?;
    if !verify_checksum(prefix, decoded.iter().cloned()) {
        return Err(AddressError::InvalidChecksum);
    }
    let converted = convert_bits(decoded.iter().cloned(), 5, 8, true).unwrap();
    let mut addr = [0; 20];
    addr.copy_from_slice(&converted[1 .. converted.len()-6]);
    Ok((
        addr,
        match converted[0] {
            0 => AddressType::P2PKH,
            8 => AddressType::P2SH,
            x => return Err(AddressError::InvalidAddressType(x)),
        },
        prefix.to_string(),
    ))
}

#[derive(Clone, Debug)]
pub struct Address {
    addr_type: AddressType,
    bytes: [u8; 20],
    cash_addr: String,
    prefix: String,
}

impl Address {
    pub fn from_bytes(addr_type: AddressType, bytes: [u8; 20]) -> Self {
        Address {
            cash_addr: to_cash_addr(DEFAULT_PREFIX, addr_type, &bytes),
            addr_type,
            prefix: DEFAULT_PREFIX.to_string(),
            bytes,
        }
    }

    pub fn from_bytes_prefix(prefix: &str, addr_type: AddressType, bytes: [u8; 20]) -> Self {
        Address {
            cash_addr: to_cash_addr(prefix, addr_type, &bytes),
            addr_type,
            prefix: prefix.to_string(),
            bytes,
        }
    }

    pub fn from_cash_addr(cash_addr: String) -> Result<Self, AddressError> {
        let (bytes, addr_type, prefix) = from_cash_addr(&cash_addr)?;
        Ok(Address { bytes, addr_type, cash_addr, prefix })
    }

    pub fn from_pub_key(prefix: &str, pub_key: &secp256k1::PublicKey) -> Self {
        Address::from_bytes_prefix(prefix, AddressType::P2PKH,
                                   crate::hash::hash160(&pub_key.serialize()))
    }

    pub fn bytes(&self) -> &[u8; 20] {
        &self.bytes
    }

    pub fn cash_addr(&self) -> &str {
        &self.cash_addr
    }

    pub fn addr_type(&self) -> AddressType {
        self.addr_type
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}
