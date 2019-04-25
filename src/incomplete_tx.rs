use crate::tx::{TxInput, TxOutput, TxOutpoint, Tx};
use crate::script::*;
use crate::hash::{double_sha256};
use crate::serialize::write_var_int;

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use secp256k1::{Secp256k1, PublicKey, SecretKey, Message};

pub trait Output {
    fn value(&self) -> u64;
    fn script(&self) -> Script;
    fn script_code(&self) -> Script;
    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  pub_key: &secp256k1::PublicKey,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script;
}


pub struct Utxo {
    pub outpoint: TxOutpoint,
    pub output: Box<dyn Output>,
    pub sequence: u32,
    pub key: SecretKey,
}

#[derive(Clone, Debug)]
pub struct PreImage {
    pub version: i32,
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub outpoint: TxOutpoint,
    pub script_code: Script,
    pub value: u64,
    pub sequence: u32,
    pub hash_outputs: [u8; 32],
    pub lock_time: u32,
    pub sighash_type: u32,
}

pub struct IncompleteTx {
    version: i32,
    inputs: Vec<Utxo>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

impl IncompleteTx {
    pub fn new_simple() -> Self {
        IncompleteTx {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn add_utxo(&mut self, utxo: Utxo) -> usize {
        self.inputs.push(utxo);
        self.inputs.len() - 1
    }

    pub fn add_output<O: Output>(&mut self, output: &O) -> usize {
        self.outputs.push(
            TxOutput::new(output.value(), output.script())
        );
        self.outputs.len() - 1
    }

    pub fn replace_output<O: Output>(&mut self, idx: usize, output: &O) {
        self.outputs[idx] = TxOutput::new(output.value(), output.script());
    }

    pub fn remove_output(&mut self, idx: usize) {
        self.outputs.remove(idx);
    }

    pub fn pre_images(&self, sighash_type: u32) -> Vec<PreImage> {
        let mut hash_prevouts = [0u8; 32];
        let mut hash_sequence = [0u8; 32];
        let mut hash_outputs = [0u8; 32];
        {
            let mut outpoints_serialized = Vec::new();
            for input in self.inputs.iter() {
                outpoints_serialized.write(&input.outpoint.tx_hash).unwrap();
                outpoints_serialized.write_u32::<LittleEndian>(input.outpoint.output_idx).unwrap();
            }
            hash_prevouts.copy_from_slice(&double_sha256(&outpoints_serialized));
        }
        {
            let mut sequence_serialized = Vec::new();
            for input in self.inputs.iter() {
                sequence_serialized.write_u32::<LittleEndian>(input.sequence).unwrap();
            }
            hash_sequence.copy_from_slice(&double_sha256(&sequence_serialized));
        }
        {
            let mut outputs_serialized = Vec::new();
            for output in self.outputs.iter() {
                output.write_to_stream(&mut outputs_serialized).unwrap();
            }
            hash_outputs.copy_from_slice(&double_sha256(&outputs_serialized));
        }
        let mut pre_images = Vec::new();
        for input in self.inputs.iter() {
            pre_images.push(PreImage {
                version: self.version,
                hash_prevouts: hash_prevouts.clone(),
                hash_sequence: hash_sequence.clone(),
                outpoint: input.outpoint.clone(),
                script_code: input.output.script_code(),
                value: input.output.value(),
                sequence: input.sequence,
                hash_outputs: hash_outputs.clone(),
                lock_time: self.lock_time,
                sighash_type,
            });
        }
        pre_images
    }

    pub fn sign(&self) -> Tx {
        let secp = Secp256k1::new();  // TODO: setup beforehand
        let sighash_type: u32 = 0x41;
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        for (input, pre_image) in self.inputs.iter().zip(self.pre_images(sighash_type)) {
//            let mut pre_image = Vec::new();
//            pre_image.write_i32::<LittleEndian>(self.version).unwrap();
//            pre_image.write(&hash_prevouts).unwrap();
//            pre_image.write(&hash_sequence).unwrap();
//            pre_image.write(&input.outpoint.tx_hash).unwrap();
//            pre_image.write_u32::<LittleEndian>(input.outpoint.output_idx).unwrap();
//            let script = input.output.script_code().to_vec();
//            println!("{}", input.output.script_code());
//            write_var_int(&mut pre_image, script.len() as u64).unwrap();
//            pre_image.write(&script).unwrap();
//            pre_image.write_u64::<LittleEndian>(input.output.value()).unwrap();
//            pre_image.write_u32::<LittleEndian>(input.sequence).unwrap();
//            pre_image.write(&hash_outputs).unwrap();
//            pre_image.write_u32::<LittleEndian>(self.lock_time).unwrap();
//            pre_image.write_u32::<LittleEndian>(sighash_type).unwrap();
            let mut pre_image_serialized = Vec::new();
            pre_image.write_to_stream(&mut pre_image_serialized).unwrap();
            let message = Message::from_slice(&double_sha256(&pre_image_serialized)).unwrap();
            let pub_key = PublicKey::from_secret_key(&secp, &input.key);
            let sig = secp.sign(&message, &input.key);
            let mut sig_ser = sig.serialize_der().to_vec();
            sig_ser.push(sighash_type as u8);
            let script = input.output.sig_script(sig_ser, &pub_key, &pre_image, &self.outputs);
            tx_inputs.push(TxInput::new(input.outpoint.clone(), script, input.sequence));
        }
        Tx::new(self.version, tx_inputs, self.outputs.clone(), self.lock_time)
    }

    pub fn estimate_size(&self) -> u64 {
        use std::mem::{size_of_val};
        let mut size = 0;
        size += size_of_val(&self.version) as u64;
        size += self.inputs.len() as u64 * 148;  // TODO: estimate non pkh inputs
        size += 1;  // number of inputs
        size += self.outputs.iter().map(|output| output.script.to_vec().len() as u64).sum::<u64>();
        size += size_of_val(&self.lock_time) as u64; // time lock
        size
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PreImageWriteFlags {
    pub version: bool,
    pub hash_prevouts: bool,
    pub hash_sequence: bool,
    pub outpoint: bool,
    pub script_code: bool,
    pub value: bool,
    pub sequence: bool,
    pub hash_outputs: bool,
    pub lock_time: bool,
    pub sighash_type: bool,
}

impl PreImage {
    pub fn write_to_stream_flags<W: Write>(&self,
                                           write: &mut W,
                                           flags: PreImageWriteFlags) -> std::io::Result<()> {
        if flags.version       { write.write_i32::<LittleEndian>(self.version)?; }
        if flags.hash_prevouts { write.write(&self.hash_prevouts)?; }
        if flags.hash_sequence { write.write(&self.hash_sequence)?; }
        if flags.outpoint {
            write.write(&self.outpoint.tx_hash)?;
            write.write_u32::<LittleEndian>(self.outpoint.output_idx)?;
        }
        if flags.script_code {
            let script = self.script_code.to_vec();
            write_var_int(write, script.len() as u64)?;
            write.write(&script)?;
        }
        if flags.value        { write.write_u64::<LittleEndian>(self.value)?; }
        if flags.sequence     { write.write_u32::<LittleEndian>(self.sequence)?; }
        if flags.hash_outputs { write.write(&self.hash_outputs)?; }
        if flags.lock_time    { write.write_u32::<LittleEndian>(self.lock_time)?; }
        if flags.sighash_type { write.write_u32::<LittleEndian>(self.sighash_type)?; }
        Ok(())
    }

    pub fn write_to_stream<W: Write>(&self, write: &mut W) -> std::io::Result<()> {
        self.write_to_stream_flags(write, PreImageWriteFlags {
            version: true,
            hash_prevouts: true,
            hash_sequence: true,
            outpoint: true,
            script_code: true,
            value: true,
            sequence: true,
            hash_outputs: true,
            lock_time: true,
            sighash_type: true,
        })
    }
}

impl std::fmt::Display for PreImage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "version: {}", self.version)?;
        writeln!(f, "hash_prevouts: {}", hex::encode(self.hash_prevouts))?;
        writeln!(f, "hash_sequence: {}", hex::encode(self.hash_sequence))?;
        writeln!(f, "outpoint.tx_hash: {}", hex::encode(self.outpoint.tx_hash))?;
        writeln!(f, "outpoint.output_idx: {}", self.outpoint.output_idx)?;
        writeln!(f, "script_code: {}", hex::encode(self.script_code.to_vec()))?;
        writeln!(f, "value: {}", self.value)?;
        writeln!(f, "sequence: {}", self.sequence)?;
        writeln!(f, "hash_outputs: {}", hex::encode(self.hash_outputs))?;
        writeln!(f, "lock_time: {}", self.lock_time)?;
        writeln!(f, "sighash_type: {:x}", self.sighash_type)?;
        Ok(())
    }
}