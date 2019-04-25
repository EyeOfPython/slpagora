use crate::address::Address;
use crate::incomplete_tx::{Output, PreImage, PreImageWriteFlags};
use crate::tx::TxOutput;
use crate::script::{Script, Op, OpCodeType};
use crate::hash::hash160;

use byteorder::{BigEndian, WriteBytesExt};

#[derive(Clone, Debug)]
pub struct P2PKHOutput {
    pub value: u64,
    pub address: Address,
}

//#[derive(Clone, Debug)]
pub struct P2SHOutput<O: Output> {
    pub output: O,
}

#[derive(Clone, Debug)]
pub struct P2PKHDsvOutput {
    pub value: u64,
    pub address: Address,
}

#[derive(Clone, Debug)]
pub struct OpReturnOutput {
    pub pushes: Vec<Vec<u8>>,
    pub is_minimal_push: bool,
}

#[derive(Clone, Debug)]
pub struct SLPSendOutput {
    pub token_type: u8,
    pub token_id: [u8; 32],
    pub output_quantities: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct TradeOfferOutput {
    pub tx_id: [u8; 32],
    pub output_idx: u32,
    pub sell_amount: u64,
    pub buy_amount: u64,
    pub receiving_address: Address,
    pub cancel_address: Address,
}

pub struct EnforceOutputsOutput {
    pub value: u64,
    pub cancel_address: Address,
    pub enforced_outputs: Vec<Box<dyn Output>>,

    pub is_cancel: Option<bool>, // None if just generating P2SH
}

impl Output for P2PKHOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        Script::new(vec![
            Op::Code(OpCodeType::OpDup),
            Op::Code(OpCodeType::OpHash160),
            Op::Push(self.address.bytes().to_vec()),
            Op::Code(OpCodeType::OpEqualVerify),
            Op::Code(OpCodeType::OpCheckSig),
        ])
    }

    fn script_code(&self) -> Script {
        self.script()
    }

    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  pub_key: &secp256k1::PublicKey,
                  _pre_image: &PreImage,
                  _outputs: &[TxOutput]) -> Script {
        Script::new(vec![
            Op::Push(serialized_sig),
            Op::Push(pub_key.serialize().to_vec()),
        ])
    }
}

impl<O: Output> Output for P2SHOutput<O> {
    fn value(&self) -> u64 {
        self.output.value()
    }

    fn script(&self) -> Script {
        Script::new(vec![
            Op::Code(OpCodeType::OpHash160),
            Op::Push(hash160(&self.output.script().to_vec()).to_vec()),
            Op::Code(OpCodeType::OpEqual),
        ])
    }

    fn script_code(&self) -> Script {
        self.output.script()
    }

    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  pub_key: &secp256k1::PublicKey,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script {
        let mut script = self.output.sig_script(serialized_sig, pub_key, pre_image, outputs);
        script.add_op(Op::Push(self.output.script().to_vec()));
        script
    }
}

impl Output for P2PKHDsvOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        use crate::script::OpCodeType::*;
        Script::new(vec![
            Op::Code(Op2Dup),
            Op::Code(OpDup),
            Op::Code(OpHash160),
            Op::Push(self.address.bytes().to_vec()),
            Op::Code(OpEqualVerify),
            Op::Code(OpSwap),
            Op::Push(vec![0x41]),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCheckSigVerify),
            Op::Code(OpRot),
            Op::Code(OpSha256),
            Op::Code(OpSwap),
            Op::Code(OpCheckDataSig),
        ])
    }

    fn script_code(&self) -> Script {
        self.script()
    }

    fn sig_script(&self,
                  mut serialized_sig: Vec<u8>,
                  pub_key: &secp256k1::PublicKey,
                  pre_image: &PreImage,
                  _outputs: &[TxOutput]) -> Script {
        let mut pre_image_serialized = Vec::new();
        pre_image.write_to_stream(&mut pre_image_serialized).unwrap();
        serialized_sig.remove(serialized_sig.len() - 1);
        let pub_key = pub_key.serialize().to_vec();
        Script::new(vec![
            Op::Push(pre_image_serialized),
            Op::Push(serialized_sig),
            Op::Push(pub_key),
        ])
    }
}

impl Output for OpReturnOutput {
    fn value(&self) -> u64 {
        0
    }

    fn script(&self) -> Script {
        let mut script_ops = vec![
            Op::Code(OpCodeType::OpReturn),
        ];
        script_ops.extend(self.pushes.iter().cloned().map(Op::Push));
        if self.is_minimal_push {
            Script::new(script_ops)
        } else {
            Script::new_non_minimal_push(script_ops)
        }
    }

    fn script_code(&self) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }

    fn sig_script(&self, _: Vec<u8>, _: &secp256k1::PublicKey, _: &PreImage,
                  _: &[TxOutput]) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }
}

impl Output for EnforceOutputsOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        use crate::script::OpCodeType::*;
        let mut outputs_pre = Vec::new();
        self.enforced_outputs.iter()
            .map(|output|
                TxOutput::new(output.value(), output.script())
            )
            .for_each(|tx_output| tx_output.write_to_stream(&mut outputs_pre).unwrap());
        Script::new(vec![
            Op::Code(OpIf),

            Op::Push(outputs_pre),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpHash256),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpSha256),
            Op::Code(Op3Dup),
            Op::Code(OpDrop),
            Op::Push(vec![0x41]),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCheckSigVerify),
            Op::Code(OpRot),
            Op::Code(OpCheckDataSig),

            Op::Code(OpElse),

            Op::Code(OpDup),
            Op::Code(OpHash160),
            Op::Push(self.cancel_address.bytes().to_vec()),
            Op::Code(OpEqualVerify),
            Op::Code(OpCheckSig),

            Op::Code(OpEndIf),
        ])
    }

    fn script_code(&self) -> Script {
        self.script()
    }

    fn sig_script(&self,
                  mut serialized_sig: Vec<u8>,
                  pub_key: &secp256k1::PublicKey,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script {
        let pub_key = pub_key.serialize().to_vec();
        if self.is_cancel.expect("Must set is_cancel for signing") {
            Script::new(vec![
                Op::Push(serialized_sig),
                Op::Push(pub_key),
                Op::Push(vec![0x00]),
            ])
        } else {
            serialized_sig.remove(serialized_sig.len() - 1);
            let mut pre_image_begin = Vec::new();
            let mut pre_image_end = Vec::new();
            let mut outputs_end = Vec::new();
            pre_image.write_to_stream_flags(&mut pre_image_begin, PreImageWriteFlags {
                version: true,
                hash_prevouts: true,
                hash_sequence: true,
                outpoint: true,
                script_code: true,
                value: true,
                sequence: true,
                hash_outputs: false,
                lock_time: false,
                sighash_type: false,
            }).unwrap();
            pre_image.write_to_stream_flags(&mut pre_image_end, PreImageWriteFlags {
                version: false,
                hash_prevouts: false,
                hash_sequence: false,
                outpoint: false,
                script_code: false,
                value: false,
                sequence: false,
                hash_outputs: false,
                lock_time: true,
                sighash_type: true,
            }).unwrap();
            outputs[self.enforced_outputs.len()..].iter()
                .map(|output|
                    TxOutput::new(output.value, output.script.clone())
                )
                .for_each(|tx_output| {
                    tx_output.write_to_stream(&mut outputs_end).unwrap()
                });
            Script::new(vec![
                Op::Push(pub_key),
                Op::Push(serialized_sig),
                Op::Push(pre_image_end),
                Op::Push(pre_image_begin),
                Op::Push(outputs_end),
                Op::Push(vec![0x01]),
            ])
        }
    }
}

impl Output for SLPSendOutput {
    fn value(&self) -> u64 {
        0
    }

    /* From the spec:
     * OP_RETURN
     * <lokad id: 'SLP\x00'> (4 bytes, ascii)
     * <token_type: 1> (1 to 2 byte integer)
     * <transaction_type: 'SEND'> (4 bytes, ascii)
     * <token_id> (32 bytes)
     * <token_output_quantity1> (required, 8 byte integer)
     * <token_output_quantity2> (optional, 8 byte integer)
     * ...
     * <token_output_quantity19> (optional, 8 byte integer) */

    fn script(&self) -> Script {
        let mut script_ops = vec![
            Op::Code(OpCodeType::OpReturn),
            Op::Push(b"SLP\0".to_vec()),
            Op::Push(vec![self.token_type]),
            Op::Push(b"SEND".to_vec()),
            Op::Push(self.token_id.to_vec()),
        ];
        script_ops.extend(self.output_quantities.iter().map(|quantity| {
            let mut data = Vec::new();
            data.write_u64::<BigEndian>(*quantity).unwrap();
            Op::Push(data)
        }));
        Script::new_non_minimal_push(script_ops)
    }

    fn script_code(&self) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }

    fn sig_script(&self, _: Vec<u8>, _: &secp256k1::PublicKey, _: &PreImage,
                  _: &[TxOutput]) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }
}

impl TradeOfferOutput {
    pub fn into_output(self) -> OpReturnOutput {
        OpReturnOutput {
            pushes: vec![
                b"EXCH".to_vec(), // 0: lokad id
                b"\x01".to_vec(), // 1: version id
                b"SELL".to_vec(), // 2: trade type

                self.tx_id.to_vec(),  // 3: tx id

                {
                    let mut output_idx_serialized = Vec::new();
                    output_idx_serialized.write_u32::<BigEndian>(self.output_idx).unwrap();
                    output_idx_serialized  // 4: output idx
                },
                {
                    let mut sell_amount_serialized = Vec::new();
                    sell_amount_serialized.write_u64::<BigEndian>(self.sell_amount).unwrap();
                    sell_amount_serialized  // 5: sell amount
                },
                {
                    let mut buy_amount_serialized = Vec::new();
                    buy_amount_serialized.write_u64::<BigEndian>(self.buy_amount).unwrap();
                    buy_amount_serialized  // 6: buy amount
                },
                self.receiving_address.bytes().to_vec(),  // 7: receiving address
                self.cancel_address.bytes().to_vec(),  // 8: cancel address
            ],
            is_minimal_push: false,
        }
    }
}
