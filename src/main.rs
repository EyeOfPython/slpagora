pub mod message_header;
pub mod message;
pub mod message_error;
pub mod version_message;
pub mod hash;
pub mod serialize;
pub mod tx;
pub mod incomplete_tx;
pub mod script;
pub mod script_interpreter;
pub mod address;
pub mod outputs;
pub mod wallet;
pub mod trade;
pub mod display_qr;

use std::io::{self, Write, Read};
use text_io::{read, try_read, try_scan};
use std::env;


const WALLET_FILE_NAME: &str = "trade.dat";
const SLP_AGORA_PATH: &str = ".slpagora";


fn ensure_wallet_interactive() -> Result<wallet::Wallet, Box<std::error::Error>> {
    let trades_dir = dirs::home_dir().unwrap_or(env::current_dir()?).join(SLP_AGORA_PATH);
    let wallet_file_path = trades_dir.as_path().join(WALLET_FILE_NAME);
    std::fs::create_dir_all(trades_dir)?;
    match std::fs::File::open(&wallet_file_path) {
        Ok(mut file) => {
            println!("Using wallet file at {}", wallet_file_path.display());
            let mut secret_bytes = [0; 32];
            file.read(&mut secret_bytes)?;
            Ok(wallet::Wallet::from_secret(&secret_bytes)?)
        },
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
            println!("Creating wallet at {}", wallet_file_path.display());
            use rand::RngCore;
            let mut rng = rand::rngs::OsRng::new().unwrap();
            let mut secret_bytes = [0; 32];
            rng.fill_bytes(&mut secret_bytes);
            let _ = secp256k1::SecretKey::from_slice(&secret_bytes)?;
            std::fs::File::create(wallet_file_path)?.write(&secret_bytes)?;
            Ok(wallet::Wallet::from_secret(&secret_bytes)?)
        },
        err => {err?; unreachable!()},
    }
}

fn show_balance(w: &wallet::Wallet) {
    let balance = w.get_balance();
    println!("Your wallet's balance is: {} sats or {} BCH.",
             balance,
             balance as f64 / 100_000_000.0);
    println!("Your wallet's address is: {}", w.address().cash_addr());
    display_qr::display(w.address().cash_addr().as_bytes());
}

fn do_transaction(w: &wallet::Wallet) -> Result<(), Box<std::error::Error>> {
    let (mut tx_build, balance) = w.init_transaction();
    println!("Your wallet's balance is: {} sats or {} BCH.",
             balance,
             balance as f64 / 100_000_000.0);
    if balance < w.dust_amount() {
        println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                  BCH to your wallet's address: {}", balance, w.address().cash_addr());
        return Ok(());
    }
    print!("Enter the address to send to: ");
    io::stdout().flush()?;
    let addr_str: String = read!("{}\n");
    let addr_str = addr_str.trim();
    let receiving_addr = match address::Address::from_cash_addr(addr_str.to_string())  {
        Ok(addr) => addr,
        Err(err) => {
            println!("Please enter a valid address: {:?}", err);
            return Ok(());
        }
    };
    if receiving_addr.prefix() == "simpleledger" {
        println!("Note: You entered a Simple Ledger Protocol (SLP) address, but this wallet only \
                  contains ordinary non-token BCH. The program will proceed anyways.");
    }
    print!("Enter the amount in satoshis to send, or \"all\" (without quotes) to send the entire \
            balance: ");
    io::stdout().flush()?;
    let send_amount_str: String = read!("{}\n");
    let send_amount_str = send_amount_str.trim();
    let send_amount = if send_amount_str == "all" {
        balance
    } else {
        send_amount_str.parse::<u64>()?
    };
    let mut output_send = outputs::P2PKHOutput {
        value: send_amount,
        address: receiving_addr,
    };
    let send_idx = tx_build.add_output(&output_send);
    let mut output_back_to_wallet = outputs::P2PKHOutput {
        value: 0,
        address: w.address().clone(),
    };
    let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);
    let estimated_size = tx_build.estimate_size();
    let send_back_to_wallet_amount = if balance < send_amount + (estimated_size + 5) {
        output_send.value = balance - (estimated_size + 5);
        tx_build.replace_output(send_idx, &output_send);
        0
    } else {
        balance - (send_amount + estimated_size + 5)
    };
    if send_back_to_wallet_amount < w.dust_amount() {
        tx_build.remove_output(back_to_wallet_idx);
    } else {
        output_back_to_wallet.value = send_back_to_wallet_amount;
        tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    }
    let tx = tx_build.sign();
    let response = w.send_tx(&tx)?;
    println!("Sent transaction. Transaction ID is: {}", response);

    Ok(())
}

fn main() -> Result<(), Box<std::error::Error>> {
    let wallet = ensure_wallet_interactive()?;
    println!("Your wallet address is: {}", wallet.address().cash_addr());

    loop {
        println!("---------------------------------");
        println!("Select an option from below:");
        println!("1: Show wallet balance / fund wallet");
        println!("2: Send BCH from this wallet to an address");
        println!("3: Create a new trade for a token on the BCH blockchain");
        println!("4: List all available token trades on the BCH blockchain");
        println!("Anything else: Exit");
        print!("Your choice: ");
        io::stdout().flush()?;
        let choice: String = read!("{}\n");
        match choice.trim() {
            "1" => show_balance(&wallet),
            "2" => do_transaction(&wallet)?,
            "3" => trade::create_trade_interactive(&wallet)?,
            "4" => trade::accept_trades_interactive(&wallet)?,
            _ => {
                println!("Bye, have a great time!");
                return Ok(());
            },
        }
    }
}
