use crate::wallet::Wallet;
use crate::outputs::{EnforceOutputsOutput, SLPSendOutput, P2PKHOutput, TradeOfferOutput, P2SHOutput};
use crate::address::{Address, AddressType};
use crate::hash::hash160;
use crate::incomplete_tx::{Output, Utxo};
use crate::tx::{tx_hex_to_hash, TxOutpoint};
use crate::script::{Script, Op, OpCodeType};
use std::io::{self, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use text_io::{read, try_read, try_scan};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};


#[derive(Deserialize, Serialize, Debug)]
pub struct TokenEntry {
    id: String,
    timestamp: String,
    symbol: Option<String>,
    name: Option<String>,
    #[serde(alias = "documentUri")]
    document_uri: Option<String>,
    #[serde(alias = "documentHash")]
    document_hash: Option<String>,
    decimals: u64,
    #[serde(alias = "initialTokenQty")]
    initial_token_qty: f64,
}

#[derive(Deserialize, Serialize, Debug)]
struct TradeEntryTx {
    h: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct TradeEntryOut {
    h1: Option<String>,
    h2: Option<String>,
    h3: Option<String>,
    h4: Option<String>,
    h5: Option<String>,
    h6: Option<String>,
    h7: Option<String>,
    h8: Option<String>,
    h9: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SlpTxValidity {
    txid: String,
    valid: bool,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetails {
    txid: String,
    vout: Vec<TxDetailsVout>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetailsVout {
    value: String,
    #[serde(alias = "scriptPubKey")]
    script_pub_key: TxDetailsScriptPubKey,
    #[serde(alias = "spentTxId")]
    spent_tx_id: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetailsScriptPubKey {
    hex: String,
    r#type: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TradeEntry {
    tx: TradeEntryTx,
    out: Vec<TradeEntryOut>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TradesResult {
    c: Vec<TradeEntry>,
}

fn fetch_tokens(name: Option<&str>) -> Result<Vec<TokenEntry>, Box<std::error::Error>> {
    let url = format!("https://rest.bitcoin.com/v2/slp/list/{}", name.unwrap_or(""));
    if name.and_then(|s| if s == "" {None} else {Some(s)}).is_some() {
        Ok(reqwest::get(&url)?.json().map(|x| vec![x]).unwrap_or(vec![]))
    } else {
        Ok(reqwest::get(&url)?.json()?)
    }
}

fn option_str(s: &Option<String>) -> &str {
    s.as_ref().map(|x| x.as_str()).unwrap_or("<empty>")
}

pub fn create_trade_interactive(wallet: &Wallet) -> Result<(), Box<std::error::Error>> {
    print!("Enter the token id or token name/symbol you want to sell: ");
    io::stdout().flush()?;
    let token_str: String = read!("{}\n");

    let mut tokens_found = fetch_tokens(Some(&token_str))?;
    if tokens_found.len() == 0 {
        let all_tokens = fetch_tokens(None)?;
        let mut tokens_found_name = all_tokens.into_iter().filter(|token| {
            token.name.as_ref() == Some(&token_str) || token.symbol.as_ref() == Some(&token_str)
        }).collect::<Vec<_>>();
        if tokens_found_name.len() == 0 {
            println!("Didn't find any tokens with id/name/hash '{}'.", token_str);
            return Ok(())
        }
        tokens_found.append(&mut tokens_found_name);
    }
    let token = if tokens_found.len() == 1 {
        tokens_found.remove(0)
    } else {
        println!("Found multiple tokens with those criteria: ");
        println!(
            "{:3} {:64} {:>12} {:20} {}",
            "#",
            "ID",
            "Symbol",
            "Name",
            "Uri",
        );
        for (i, token) in tokens_found.iter().enumerate() {
            println!(
                "{:3} {:64} {:>12} {:20} {}",
                i,
                token.id,
                option_str(&token.symbol),
                option_str(&token.name),
                option_str(&token.document_uri),
            );
        }
        print!("Enter the number (0-{}) you want to sell: ", tokens_found.len() - 1);
        io::stdout().flush()?;
        let token_idx_str: String = read!("{}\n");
        if token_idx_str.len() == 0 {
            println!("Bye, have a great time!");
            return Ok(());
        }
        match token_idx_str.parse::<usize>() {
            Ok(token_idx) => if tokens_found.len() > token_idx {
                tokens_found.remove(token_idx)
            } else {
                println!("Index {} not in the list. Exit.", token_idx);
                return Ok(())
            },
            Err(err) => {
                println!("Invalid number: {}", err);
                println!("Exit.");
                return Ok(())
            }
        }
    };

    println!("Selected token: ");
    println!("{:>18} {}", "ID:", token.id);
    println!("{:>18} {}", "Timestamp:", token.timestamp);
    println!("{:>18} {}", "Symbol:", option_str(&token.symbol));
    println!("{:>18} {}", "Name:", option_str(&token.name));
    println!("{:>18} {}", "Document URI:", option_str(&token.document_uri));
    println!("{:>18} {}", "Document Hash:", option_str(&token.document_hash));
    println!("{:>18} {}", "Decimals:", token.decimals);
    println!("{:>18} {}", "Initial Token Qty:", token.initial_token_qty);

    print!("Enter the amount of {} you want to sell (decimal): ", option_str(&token.symbol));
    io::stdout().flush()?;
    let sell_amount_str: String = read!("{}\n");
    let sell_amount_display: f64 = sell_amount_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;
    let sell_amount = (sell_amount_display * (10.0f64).powi(token.decimals as i32)) as u64;

    print!("Enter the amount of BCH you want to receive (satoshis): ");
    io::stdout().flush()?;
    let buy_amount_str: String = read!("{}\n");
    let buy_amount: u64 = buy_amount_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;

    confirm_trade_interactive(wallet,
                              &token,
                              sell_amount,
                              sell_amount_display,
                              buy_amount)?;

    Ok(())
}

fn confirm_trade_interactive(w: &Wallet,
                             token: &TokenEntry,
                             sell_amount: u64,
                             sell_amount_display: f64,
                             buy_amount: u64) -> Result<(), Box<std::error::Error>> {
    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&token.id)?);
    let receiving_address = w.address().clone();
    let cancel_address = w.address().clone();
    let output = EnforceOutputsOutput {
        value: 0,  // ignored for script hash generation
        enforced_outputs: vec![
            Box::new(SLPSendOutput {
                token_type: 1,
                token_id,
                output_quantities: vec![0, sell_amount],
            }),
            Box::new(P2PKHOutput {
                value: buy_amount,
                address: receiving_address.clone(),
            }),
        ],
        cancel_address: cancel_address.clone(),
        is_cancel: None,
    };
    let pkh = hash160(&output.script().to_vec());
    let addr_slp = Address::from_bytes_prefix(
        "simpleledger",
        AddressType::P2SH,
        pkh.clone(),
    );
    let addr_bch = Address::from_bytes_prefix(
        "bitcoincash",
        AddressType::P2SH,
        pkh,
    );
    println!("--------------------------------------------------");
    println!("Please send EXACTLY {} {} to the following address:",
             sell_amount_display,
             option_str(&token.symbol));
    println!("{}", addr_slp.cash_addr());
    println!();
    println!("Sending a different amount or incorrect token will likely burn the tokens.");

    println!("\nDO NOT CLOSE THIS PROGRAM YET BEFORE OR AFTER YOU SENT THE PAYMENT");

    println!("Waiting for transaction...");

    let utxo = w.wait_for_transaction(&addr_bch);

    println!("Received tx: {}", utxo.txid);

    let (mut tx_build, balance) = w.init_transaction();
    tx_build.add_output(&TradeOfferOutput {
        tx_id: tx_hex_to_hash(&utxo.txid),
        output_idx: utxo.vout,
        sell_amount,
        buy_amount,
        receiving_address: receiving_address.clone(),
        cancel_address: cancel_address.clone(),
    }.into_output());
    let size_so_far = tx_build.estimate_size();
    let mut send_output = P2PKHOutput {
        value: 0,
        address: w.address().clone(),
    };
    let size_output = send_output.script().to_vec().len() as u64;
    send_output.value = balance - (size_so_far + size_output) - 20;
    tx_build.add_output(&send_output);

    let tx = tx_build.sign();
    let result = w.send_tx(&tx)?;
    println!("The trade listing transaction ID is: {}", result);

    Ok(())
}

pub fn accept_trades_interactive(wallet: &Wallet) -> Result<(), Box<std::error::Error>> {
    println!("Loading trades... (Note: this might take a few seconds and a trade might need to be \
              confirmed to show up due to bitdb)");

    let trades_result: TradesResult = reqwest::get(
        "https://bitdb.bitcoin.com/q/ewogICJ2IjogMywKICAicSI6IHsKICAgICJmaW5kIjogewogICAgICAib3V0Ln\
         MxIjogIkVYQ0giLAogICAgICAib3V0LmgyIjogIjAxIiwKICAgICAgIm91dC5zMyI6ICJTRUxMIgogICAgfQogIH0K\
         fQ=="
    )?.json()?;

    let mut trades = Vec::new();
    trades_result.c.iter().for_each(|tx| tx.out.iter().for_each(|out| {
        (|| -> Option<()> {
            if out.h1.as_ref() != Some(&hex::encode(b"EXCH")) {
                return None;
            }
            trades.push(TradeOfferOutput {
                tx_id: {
                    let mut tx_id = [0; 32];
                    tx_id.copy_from_slice(&hex::decode(out.h4.as_ref()?).unwrap());
                    tx_id
                },
                output_idx: Cursor::new(hex::decode(out.h5.as_ref()?).unwrap()).read_u32::<BigEndian>().unwrap(),
                sell_amount: Cursor::new(hex::decode(out.h6.as_ref()?).unwrap()).read_u64::<BigEndian>().unwrap(),
                buy_amount: Cursor::new(hex::decode(out.h7.as_ref()?).unwrap()).read_u64::<BigEndian>().unwrap(),
                receiving_address: Address::from_bytes(AddressType::P2PKH, {
                    let mut addr = [0; 20];
                    addr.copy_from_slice(&hex::decode(out.h8.as_ref()?).unwrap());
                    addr
                }),
                cancel_address: Address::from_bytes(AddressType::P2PKH, {
                    let mut addr = [0; 20];
                    addr.copy_from_slice(&hex::decode(out.h9.as_ref()?).unwrap());
                    addr
                }),
            });
            None
        })();
    }));

    let tx_hashes = trades.iter().map(|trade| {
        hex::encode(&trade.tx_id.iter().cloned().rev().collect::<Vec<_>>())
    }).collect::<Vec<_>>();

    let trades_validity: Vec<SlpTxValidity> = reqwest::Client::new()
        .post("https://rest.bitcoin.com/v2/slp/validateTxid")
        .json(&vec![("txids", tx_hashes)].into_iter().collect::<HashMap<_, _>>())
        .send()?
        .json()?;

    let valid_txs = trades_validity.into_iter()
        .filter(|validity| validity.valid)
        .map(|validity| validity.txid)
        .collect::<HashSet<_>>();

    let tx_details: Vec<TxDetails> = reqwest::Client::new()
        .post("https://rest.bitcoin.com/v2/transaction/details")
        .json(&vec![("txids", &valid_txs)].into_iter().collect::<HashMap<_, _>>())
        .send()?
        .json()?;

    let token_ids = tx_details.into_iter().filter_map(|tx| {
        let mut p2sh_amount = None;
        let mut tx_id = None;
        let mut token_id = None;
        for (i, out) in tx.vout.into_iter().enumerate() {
            if option_str(&out.script_pub_key.r#type) == "scripthash" && i == 1 { // enforced position
                p2sh_amount = Some((out.value.parse::<f64>().unwrap() * 100_000_000.0) as u64);
                if out.spent_tx_id.is_some() {
                    return None;
                }
                break;
            }
            if option_str(&out.script_pub_key.r#type) == "pubkeyhash" {
                continue;
            }
            let script = Script::from_serialized(
                &hex::decode(&out.script_pub_key.hex).unwrap()
            );

            if script.ops().len() < 7 || // op_return + SLP\0 + version + SEND + token_id + v1 + v2
                    script.ops()[0] != Op::Code(OpCodeType::OpReturn) ||
                    script.ops()[1] != Op::Push(b"SLP\0".to_vec()) ||
                    script.ops()[2] != Op::Push(vec![0x01]) ||
                    script.ops()[3] != Op::Push(b"SEND".to_vec()) {
                continue;
            }

            if let Op::Push(vec) = &script.ops()[4] {
                tx_id = Some(tx.txid.clone());
                token_id = Some(hex::encode(vec));
            }
        }
        Some((tx_id?, (token_id?, p2sh_amount?)))
    }).collect::<HashMap<_, _>>();

    let token_details = reqwest::Client::new()
        .post("https://rest.bitcoin.com/v2/slp/list")
        .json(&vec![(
            "tokenIds",
            token_ids.values().map(|(x, _)| x.clone()).collect::<HashSet<_>>(),
        )].into_iter().collect::<HashMap<_, _>>())
        .send()?
        .json::<Vec<TokenEntry>>()?
        .into_iter()
        .map(|token_details| (token_details.id.clone(), token_details))
        .collect::<HashMap<_, _>>();

    let valid_trades = trades.into_iter()
        .filter_map(|trade| {
            let tx_id = trade.tx_id.iter().cloned().rev().collect::<Vec<_>>();
            let tx_id_hex = hex::encode(&tx_id);
            if !valid_txs.contains(&tx_id_hex) {
                return None
            }
            let (trade_token_id, amount) = token_ids.get(&tx_id_hex)?;
            let trade_token_details = token_details.get(trade_token_id)?;
            Some((tx_id_hex, trade, trade_token_details, *amount))
        })
        .collect::<Vec<_>>();

    let (mut tx_build, balance) = wallet.init_transaction();
    println!("Your balance: {} sats", balance);
    println!("Current trade offers:");
    println!("{:^3} | {:^15} | {:^14} | {:^10} | {:^11} |",
             "#", "Selling", "Asking", "Price", "Token ID");
    println!("-------------------------------------------------------------------");
    for (idx, (_, trade, trade_token_details, _))
            in valid_trades.iter().enumerate() {
        let factor = 10.0f64.powi(-(trade_token_details.decimals as i32));
        let sell_amount_display = trade.sell_amount as f64 * factor;
        let price = trade.buy_amount as f64 / sell_amount_display;
        let symbol = option_str(&trade_token_details.symbol);
        println!("{:3} | {:8} {:<6} | {:10} sat | {:6.0} sat | {:8}... |",
                 idx,
                 sell_amount_display,
                 &symbol[..6usize.min(symbol.len())],
                 trade.buy_amount,
                 price,
                 &trade_token_details.id[..8]);
    }

    if valid_trades.len() == 0 {
        println!("There currently aren't any open trades on the entire network.");
        return Ok(());
    }

    print!("Enter the trade offer number to accept (0-{}): ", valid_trades.len() - 1);
    io::stdout().flush()?;
    let offer_idx_str: String = read!("{}\n");
    if offer_idx_str.len() == 0 {
        println!("Bye!");
        return Ok(());
    }
    let offer_idx: usize = offer_idx_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;

    let (tx_id, trade, trade_token_details, amount) =
        match valid_trades.get(offer_idx) {
            Some(trade) => trade,
            None => {
                println!("Invalid number");
                println!("Exit.");
                return Ok(());
            },
        };
    let trade: &TradeOfferOutput = trade;
    let trade_token_details: &&TokenEntry = trade_token_details;
    println!("You selected the following trade:");
    println!("{:20}{:10} {:<}",
             "Purchase amount:",
             trade.sell_amount * 10.0f64.powi(-(trade_token_details.decimals as i32)),
             option_str(&trade_token_details.symbol));
    println!("{:20}{:10} sats", "Spend amount:", trade.buy_amount);
    println!("{:20}{}", "Token ID:", trade_token_details.id);
    println!("{:20}{}", "Token symbol:", option_str(&trade_token_details.symbol));
    println!("{:20}{}", "Token name:", option_str(&trade_token_details.name));
    println!("{:20}{}", "Token timestamp:", trade_token_details.timestamp);
    println!("{:20}{}", "Token document URI:", option_str(&trade_token_details.document_uri));
    println!("------------------------------------");
    if balance < trade.buy_amount {
        println!(
            "Insufficient funds. The trade asks for {} sats but your wallet's balance is only {} sats",
            trade.buy_amount,
            balance,
        );
        println!("Note that you also need to pay for the transaction fees, which are ~1000 sats");
    }

    let addr = loop {
        print!("Enter the slp address to send the tokens to: ");
        io::stdout().flush()?;
        let receiving_addr_str: String = read!("{}\n");
        if receiving_addr_str.len() == 0 {
            println!("Bye!");
            return Ok(());
        }
        let addr = match Address::from_cash_addr(receiving_addr_str) {
            Ok(addr) => addr,
            Err(err) => {
                println!("Please enter a valid address: {:?}", err);
                continue;
            }
        };
        if addr.prefix() != "simpleledger" {
            println!("Please enter a simple ledger address, it starts with 'simpleledger'.");
            continue;
        }
        break addr;
    };

    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&trade_token_details.id)?);
    let output_slp = SLPSendOutput {
        token_type: 1,
        token_id,
        output_quantities: vec![0, trade.sell_amount],
    };
    let output_buy_amount = P2PKHOutput {
        value: trade.buy_amount,
        address: trade.receiving_address.clone(),
    };
    let input_output = EnforceOutputsOutput {
        value: *amount,
        enforced_outputs: vec![
            Box::new(output_slp.clone()),
            Box::new(output_buy_amount.clone()),
        ],
        cancel_address: trade.cancel_address.clone(),
        is_cancel: Some(false),
    };
    let output_sell_amount = P2PKHOutput {
        value: wallet.dust_amount(),
        address: addr,
    };
    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    tx_build.add_utxo(Utxo {
        outpoint: TxOutpoint {
            tx_hash: tx_hex_to_hash(&tx_id),
            output_idx: trade.output_idx,
        },
        sequence: 0xffff_ffff,
        output: Box::new(
            P2SHOutput { output: input_output },
        ),
        // arbitrary, totally randomly generated, key
        key: secp256k1::SecretKey::from_slice(b"TruthIsTreasonInTheEmpireOfLies.")?,
    });
    tx_build.add_output(&output_slp);
    tx_build.add_output(&output_buy_amount);
    tx_build.add_output(&output_sell_amount);
    let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);

    let tx = tx_build.sign();
    let estimated_size = {
        let mut tx_ser = Vec::new();
        tx.write_to_stream(&mut tx_ser)?;
        tx_ser.len() as u64
    };
    println!("The estimated transaction size is {} bytes.", estimated_size);
    let fee = estimated_size + 21;
    let total_spent =
        output_slp.value() +
            output_buy_amount.value() +
            output_sell_amount.value() +
            fee;
    if total_spent > balance {
        println!("Including fees and dust outputs, this transaction will spend {} sats, but \
                  your wallet's balance is only {} sats", total_spent, balance);
        return Ok(());
    }
    output_back_to_wallet.value = balance - total_spent;
    tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let tx = tx_build.sign();

    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser)?;

    println!("The transaction hash is:");
    println!("{}", hex::encode(&tx_ser));
    println!("After broadcasting, your balance will be {} sats.", balance - total_spent);
    println!("Should the transaction be broadcast now to seal the deal? Type \"yes\" \
              (without quotes): ");

    io::stdout().flush()?;
    let confirm_send: String = read!("{}\n");
    if confirm_send.to_ascii_lowercase().as_str() == "yes" {
        let response = wallet.send_tx(&tx)?;
        println!("Sent transaction. Transaction ID is: {}", response);
    }

    Ok(())
}
