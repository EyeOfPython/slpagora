use crate::tx::{TxInput, TxOutput, TxOutpoint, Tx};
use crate::script::{Script, Op};
use crate::hash::double_sha256;
use crate::serialize::write_var_int;

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use secp256k1::{Secp256k1, PublicKey, SecretKey, Message};

pub trait Output {
    fn value(&self) -> u64;
    fn script(&self) -> Script;
}

pub struct P2PKHOutput {
    pub value: u64,
    pub address: [u8; 20],
}

pub struct Utxo {
    pub outpoint: TxOutpoint,
    pub script: Script,
    pub sequence: u32,
    pub amount: u64,
    pub key: SecretKey,
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

    pub fn add_utxo(&mut self, utxo: Utxo) -> &mut Self {
        self.inputs.push(utxo);
        self
    }

    pub fn add_output<O: Output>(&mut self, output: &O) -> &mut Self {
        self.outputs.push(
            TxOutput::new(output.value(), output.script())
        );
        self
    }

    pub fn sign(&self) -> Tx {
        let secp = Secp256k1::new();  // TODO: setup beforehand
        let sighash_type: u32 = 0x41;
        let mut hash_prevouts = [0u8; 32];
        let mut hash_sequence = [0u8; 32];
        let mut hash_outputs = [0u8; 32];
        {
            let mut outpoints_serialized = Vec::new();
            for utxo in self.inputs.iter() {
                outpoints_serialized.write(&utxo.outpoint.tx_hash);
                outpoints_serialized.write_u32::<LittleEndian>(utxo.outpoint.output_idx).unwrap();
            }
            hash_prevouts.copy_from_slice(&double_sha256(&outpoints_serialized));
        }
        {
            let mut sequence_serialized = Vec::new();
            for utxo in self.inputs.iter() {
                sequence_serialized.write_u32::<LittleEndian>(utxo.sequence).unwrap();
            }
            hash_sequence.copy_from_slice(&double_sha256(&sequence_serialized));
        }
        {
            let mut outputs_serialized = Vec::new();
            for output in self.outputs.iter() {
                output.write_to_stream(&mut outputs_serialized);
            }
            hash_outputs.copy_from_slice(&double_sha256(&outputs_serialized));
        }
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        for input in self.inputs.iter() {
            let mut preimage = Vec::new();
            preimage.write_i32::<LittleEndian>(self.version).unwrap();
            preimage.write(&hash_prevouts).unwrap();
            preimage.write(&hash_sequence).unwrap();
            preimage.write(&input.outpoint.tx_hash).unwrap();
            preimage.write_u32::<LittleEndian>(input.outpoint.output_idx).unwrap();
            let script = input.script.to_vec();
            write_var_int(&mut preimage, script.len() as u64).unwrap();
            preimage.write(&script).unwrap();
            preimage.write_u64::<LittleEndian>(input.amount).unwrap();
            preimage.write_u32::<LittleEndian>(input.sequence).unwrap();
            preimage.write(&hash_outputs).unwrap();
            preimage.write_u32::<LittleEndian>(self.lock_time).unwrap();
            preimage.write_u32::<LittleEndian>(sighash_type).unwrap();
            let message = Message::from_slice(&double_sha256(&preimage)).unwrap();
            let pub_key = PublicKey::from_secret_key(&secp, &input.key);
            let sig = secp.sign(&message, &input.key);
            let mut sig_ser = sig.serialize_der().to_vec();
            sig_ser.push(sighash_type as u8);
            let script = Script::new(vec![
                Op::PUSH(sig_ser),
                Op::PUSH(pub_key.serialize().to_vec()),
            ]);
            tx_inputs.push(TxInput::new(input.outpoint.clone(), script, input.sequence));
        }
        Tx::new(self.version, tx_inputs, self.outputs.clone(), self.lock_time)
    }
}

impl Output for P2PKHOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        Script::new(vec![
            Op::DUP,
            Op::HASH160,
            Op::PUSH(self.address.to_vec()),
            Op::EQUALVERIFY,
            Op::CHECKSIG,
        ])
    }
}