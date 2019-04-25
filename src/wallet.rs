use crate::address::Address;
use serde::{Serialize, Deserialize};
use crate::incomplete_tx::{IncompleteTx, Utxo};
use crate::tx::{Tx, TxOutpoint, tx_hex_to_hash};
use crate::outputs::{P2PKHOutput};


pub struct Wallet {
    secret_key: secp256k1::SecretKey,
    address: Address,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount: f64,
    pub satoshis: u64,
    pub confirmations: u32,
}

#[derive(Deserialize, Serialize, Debug)]
struct UtxoResult {
    utxos: Vec<UtxoEntry>,
}

impl Wallet {
    pub fn from_secret(secret: &[u8]) -> Result<Wallet, secp256k1::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(&secret)?;
        let curve = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&curve, &secret_key);
        let addr = Address::from_pub_key("bitcoincash", &pk);
        Ok(Wallet {
            secret_key,
            address: addr,
        })
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn get_utxos(&self, address: &Address) -> Vec<UtxoEntry> {
        let result: UtxoResult = reqwest::get(
            &format!("https://rest.bitcoin.com/v2/address/utxo/{}", address.cash_addr())
        ).unwrap().json().unwrap();
        result.utxos
    }

    pub fn get_balance(&self) -> u64 {
        self.get_utxos(&self.address).iter().map(|utxo| utxo.satoshis).sum()
    }

    pub fn wait_for_transaction(&self, address: &Address) -> UtxoEntry {
        loop {
            let mut utxos = self.get_utxos(address);
            if utxos.len() > 0 {
                return utxos.remove(0)
            }
            std::thread::sleep(std::time::Duration::new(1, 0));
        }
    }

    pub fn init_transaction(&self) -> (IncompleteTx, u64) {
        let mut tx_build = IncompleteTx::new_simple();
        let mut balance = 0;
        self.get_utxos(&self.address).iter().for_each(|utxo| {
            balance += utxo.satoshis;
            tx_build.add_utxo(Utxo {
                key: self.secret_key.clone(),
                output: Box::new(P2PKHOutput {
                    address: self.address.clone(),
                    value: utxo.satoshis,
                }),
                outpoint: TxOutpoint {
                    tx_hash: tx_hex_to_hash(&utxo.txid),
                    output_idx: utxo.vout,
                },
                sequence: 0xffff_ffff,
            });
        });
        (tx_build, balance)
    }

    pub fn send_tx(&self, tx: &Tx) -> Result<String, Box<std::error::Error>> {
        let mut tx_ser = Vec::new();
        tx.write_to_stream(&mut tx_ser)?;
        Ok(reqwest::get(
            &format!(
                "https://rest.bitcoin.com/v2/rawtransactions/sendRawTransaction/{}",
                hex::encode(&tx_ser),
            ),
        )?.text()?)
    }

    pub fn dust_amount(&self) -> u64 {
        546
    }
}
