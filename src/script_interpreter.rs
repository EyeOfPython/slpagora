use crate::script::{Op, OpCodeType};
use crate::hash::{single_sha256, double_sha256};
use secp256k1::{Secp256k1, All, PublicKey, Signature, Message};

pub struct ScriptInterpreter {
    stack: Vec<Vec<u8>>,
    curve: Secp256k1<All>,
    pre_image_serialized: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum ScriptError {
    InvalidPubKey,
    InvalidSignatureFormat,
    InvalidSignature,
    NotImplemented,
}

impl ScriptInterpreter {
    pub fn new(pre_image_serialized: Vec<u8>) -> Self {
        ScriptInterpreter {
            stack: Vec::new(),
            curve: Secp256k1::new(),
            pre_image_serialized,
        }
    }

    pub fn run_op(&mut self, op: &Op) -> Result<(), ScriptError> {
        match op {
            Op::Push(data) => {
                self.stack.push(data.clone());
                Ok(())
            },
            Op::Code(code) => self.run_op_code(*code),
        }
    }

    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    pub fn print_stack(&self) {
        for (i, item) in self.stack.iter().rev().enumerate() {
            println!("{:5}: {}", i, hex::encode(item));
        }
    }

    fn run_op_code(&mut self, op_code: OpCodeType) -> Result<(), ScriptError> {
        use crate::script::OpCodeType::*;
        use crate::script_interpreter::ScriptError::*;
        match op_code {
            OpSwap => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.insert(self.stack.len() - 1, top);
            },
            OpCat => {
                let mut first = self.stack.remove(self.stack.len() - 1);
                let mut second = self.stack.remove(self.stack.len() - 1);
                second.append(&mut first);
                self.stack.push(second);
            },
            OpHash256 => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.push(double_sha256(&top).to_vec());
            },
            OpSha256 => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.push(single_sha256(&top).to_vec());
            },
            Op3Dup => {
                self.stack.extend(
                    self.stack[self.stack.len() - 3..].iter().cloned().collect::<Vec<_>>()
                );
            },
            OpDrop => {
                self.stack.remove(self.stack.len() - 1);
            },
            OpCheckSigVerify => {
                let pub_key = PublicKey::from_slice(
                    &self.stack.remove(self.stack.len() - 1)
                ).map_err(|_| InvalidPubKey)?;
                let mut sig_ser = self.stack.remove(self.stack.len() - 1);
                sig_ser.remove(sig_ser.len() - 1);
                let sig = Signature::from_der(&sig_ser)
                    .map_err(|_| InvalidSignatureFormat)?;
                let msg = Message::from_slice(&double_sha256(&self.pre_image_serialized))
                    .expect("Invalid message (this is a bug)");
                self.curve.verify(&msg, &sig, &pub_key).map_err(|_| InvalidSignature)?;
            },
            OpRot => {
                let third = self.stack.remove(self.stack.len() - 3);
                self.stack.push(third);
            },
            OpCheckDataSig => {
                let pub_key = PublicKey::from_slice(
                    &self.stack.remove(self.stack.len() - 1)
                ).map_err(|_| InvalidPubKey)?;
                let msg = Message::from_slice(
                    &single_sha256(&self.stack.remove(self.stack.len() - 1))
                ).expect("Invalid message (this is a bug)");
                let sig = Signature::from_der(&self.stack.remove(self.stack.len() - 1))
                    .map_err(|_| InvalidSignatureFormat)?;
                if let Ok(_) = self.curve.verify(&msg, &sig, &pub_key) {
                    self.stack.push(vec![1])
                } else {
                    println!("Note: OP_CHECKDATASIG failed");
                    self.stack.push(vec![0]);
                }
            },
            _ => return Err(NotImplemented),
        };
        Ok(())
    }
}
