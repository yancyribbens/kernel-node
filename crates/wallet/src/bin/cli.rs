use std::path::PathBuf;

use bitcoin::key::rand;
use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::Address;
use bitcoin::Network;
use clap::Parser;
use wallet::io::FileExt;
use wallet::silentpayments::{KeysFile, SilentPaymentKeysFile, SpendKey};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Commands {
    /// Wallet commands.
    #[command(subcommand)]
    Wallet(WalletCmd),
}

#[derive(Debug, Clone, clap::Subcommand)]
enum WalletCmd {
    /// Generate fresh scan and spend keys for receiving silent payments.
    ///
    /// By default, prints the scan key, spend private key, and spend
    /// x-only public key as hex on stdout. With `--out <path>`, writes
    /// the secrets to a binary file and prints only the spend public
    /// key on stderr. WARNING: anyone with the scan key and spend
    /// private key can spend received funds.
    GenerateKeys {
        /// Write the keys to this binary file. Must not already exist.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Generate Taproot Address.
    GenerateTaprootAddress {
        /// Write the keys to this binary file. Must not already exist.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Read Taproot Address from file.
    PrintTaprootAddressFromKeysFile { path: PathBuf },
    /// Print scan_key, spend_priv and spend_pub keys to stdout from file.
    PrintKeysFromKeysFile { path: PathBuf },
}

fn main() {
    let cli = Args::parse();

    fn generate_keys() -> (SecretKey, SecretKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let scan_priv = SecretKey::new(&mut OsRng);
        let spend_priv = SecretKey::new(&mut OsRng);
        let (spend_xonly, _) = spend_priv.public_key(&secp).x_only_public_key();
        (scan_priv, spend_priv, spend_xonly)
    }

    match cli.commands {
        Commands::Wallet(WalletCmd::GenerateKeys { out }) => {
            let (scan_priv, spend_priv, spend_pub) = generate_keys();
            match out {
                Some(path) => {
                    let file = SilentPaymentKeysFile::new(scan_priv, SpendKey::Secret(spend_priv));
                    file.save(&path).expect("failed to write keys file");
                    println!("Wrote silent payment keys to {}", path.display());
                    println!("spend_pub={}", spend_pub);
                }
                None => {
                    eprintln!("WARNING: scan_key and spend_priv must be kept secret — anyone with them can spend received funds.");
                    println!("scan_key={}", scan_priv.display_secret());
                    println!("spend_priv={}", spend_priv.display_secret());
                    println!("spend_pub={}", spend_pub);
                }
            }
        }
        Commands::Wallet(WalletCmd::GenerateTaprootAddress { out }) => {
            let s = Secp256k1::new();
            let (priv_key, pub_key) = s.generate_keypair(&mut rand::thread_rng());
            let (internal_key, _parity) = pub_key.x_only_public_key();
            let address = Address::p2tr(&s, internal_key, None, Network::Signet);

            match out {
                Some(path) => {
                    let file = KeysFile::new(priv_key);
                    file.save(&path).expect("failed to write keys file");
                    println!("Wrote silent payment keys to {}", path.display());
                    println!("address={}", address);
                }
                None => {
                    eprintln!("WARNING: private key must be kept secret — anyone with it can spend received funds.");
                    println!("address={}", address);
                    println!("private key={:?}", priv_key);
                }
            }
        }
        Commands::Wallet(WalletCmd::PrintTaprootAddressFromKeysFile { path }) => {
            let read = KeysFile::load(&path)
                .expect("file path provided should be readable as a silent payments keys file");
            let addr = read.address();
            println!("address={}", addr);
        }
        Commands::Wallet(WalletCmd::PrintKeysFromKeysFile { path }) => {
            let read = SilentPaymentKeysFile::load(&path)
                .expect("file path provided should be readable as a silent payments keys file");

            let spend_pub = read.spend_xonly();
            eprintln!("spend_pub={}", spend_pub);

            let scan_priv = read.scan_key();
            eprintln!("scan_key={}", scan_priv.display_secret());
        }
    }
}
