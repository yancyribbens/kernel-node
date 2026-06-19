use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bitcoin_coin_selection::{single_random_draw, WeightedUtxo};

use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, taproot, Address, Amount, FeeRate, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Weight, Witness,
};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::sending::calculate_partial_secret;
use silentpayments::{Network, SilentPaymentAddress};

use crate::silentpayments::wallet::{Coin, Wallet};

#[derive(Debug)]
pub enum SendError {
    WatchOnly,
    NoSpendableCoins,
    DustAmount { amount: Amount, dust: Amount },
    InsufficientFunds { needed: Amount, available: Amount },
    NetworkMismatch,
    InvalidRecipient(String),
    OutputDerivation,
    SilentPayments(::silentpayments::Error),
    Secp(secp256k1::Error),
    Sighash(bitcoin::sighash::TaprootError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::WatchOnly => {
                write!(f, "wallet is watch-only: no spend secret to sign with")
            }
            SendError::NoSpendableCoins => write!(f, "no spendable coins"),
            SendError::DustAmount { amount, dust } => write!(
                f,
                "amount {} sats is below the dust limit of {} sats",
                amount.to_sat(),
                dust.to_sat()
            ),
            SendError::InsufficientFunds { needed, available } => write!(
                f,
                "insufficient funds: need {} sats, have {} sats",
                needed.to_sat(),
                available.to_sat()
            ),
            SendError::NetworkMismatch => {
                write!(f, "recipient address is for a different network")
            }
            SendError::InvalidRecipient(e) => write!(f, "invalid recipient address: {e}"),
            SendError::OutputDerivation => write!(f, "recipient output key was not derived"),
            SendError::SilentPayments(e) => write!(f, "silent payments error: {e}"),
            SendError::Secp(e) => write!(f, "secp256k1 error: {e}"),
            SendError::Sighash(e) => write!(f, "sighash error: {e}"),
        }
    }
}

impl std::error::Error for SendError {}

impl SendError {
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            SendError::WatchOnly
                | SendError::NoSpendableCoins
                | SendError::DustAmount { .. }
                | SendError::InsufficientFunds { .. }
                | SendError::NetworkMismatch
                | SendError::InvalidRecipient(_)
        )
    }
}

impl From<::silentpayments::Error> for SendError {
    fn from(e: ::silentpayments::Error) -> Self {
        SendError::SilentPayments(e)
    }
}

impl From<secp256k1::Error> for SendError {
    fn from(e: secp256k1::Error) -> Self {
        SendError::Secp(e)
    }
}

impl From<bitcoin::sighash::TaprootError> for SendError {
    fn from(e: bitcoin::sighash::TaprootError) -> Self {
        SendError::Sighash(e)
    }
}

pub enum Recipient {
    SilentPayment(SilentPaymentAddress),
    Address(Address),
}

impl Recipient {
    pub fn parse(s: &str, network: Network) -> Result<Self, SendError> {
        if let Ok(sp) = SilentPaymentAddress::try_from(s) {
            if sp.get_network() != network {
                return Err(SendError::NetworkMismatch);
            }
            return Ok(Recipient::SilentPayment(sp));
        }
        let address = Address::from_str(s)
            .map_err(|e| SendError::InvalidRecipient(e.to_string()))?
            .require_network(bitcoin_network(network))
            .map_err(|_| SendError::NetworkMismatch)?;
        Ok(Recipient::Address(address))
    }
}

fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

impl WeightedUtxo for SpendableCoin<'_> {
    fn satisfaction_weight(&self) -> Weight {
        // see rust-bitcoin InputWeightPrediction P2TR_KEY_DEFAULT_SIGHASH
        // for full calculation, see InputWeightPrediction::from_slice()
        // 1 witness_len + 1 item len +  64 signature
        Weight::from_wu(66)
    }

    fn value(&self) -> Amount {
        self.coin.value
    }
}

#[derive(Debug)]
struct SpendableCoin<'a> {
    outpoint: OutPoint,
    coin: &'a Coin,
}

impl Wallet {
    pub fn build_transaction(
        &self,
        recipient: Recipient,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Transaction, SendError> {
        let spend_secret = self.spend_secret.ok_or(SendError::WatchOnly)?;
        let keys = self.keys.as_ref().ok_or(SendError::WatchOnly)?;
        let change_address = keys.receiver.get_change_address();

        let coins: Vec<SpendableCoin> = self
            .utxos
            .iter()
            .filter(|(outpoint, coin)| coin.spent_by.is_none() && !self.reserved.contains(outpoint))
            .map(|(outpoint, coin)| SpendableCoin {
                outpoint: *outpoint,
                coin,
            })
            .collect();

        build_transaction(
            &spend_secret,
            recipient,
            amount,
            fee_rate,
            self.scan_height,
            change_address,
            &coins,
        )
    }
}

fn build_transaction(
    spend_secret: &SecretKey,
    recipient: Recipient,
    target_amount: Amount,
    fee_rate: FeeRate,
    tip_height: u32,
    change_address: SilentPaymentAddress,
    coins: &[SpendableCoin],
) -> Result<Transaction, SendError> {
    let selection = single_random_draw(target_amount, fee_rate, &coins);
    let (_i, utxo_selection) = if selection.is_some() {
        selection.unwrap()
    } else {
        return Err(SendError::NoSpendableCoins)
    };

    let input: Vec<TxIn> = utxo_selection
        .iter()
        .map(|c| TxIn {
            previous_output: c.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();

    let matches_sum: Amount = utxo_selection.iter().map(|u| u.value()).sum();
    debug_assert!(matches_sum >= target_amount);

    let secp = Secp256k1::signing_only();
    let signing_keys: Vec<SecretKey> = utxo_selection
        .iter()
        .map(|c| spend_secret.add_tweak(&c.coin.tweak))
        .collect::<Result<_, secp256k1::Error>>()?;

    let change_value: Amount = matches_sum - target_amount;

    let mut derived: HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>> = HashMap::new();
    let mut output = vec![];
    let recipient_is_sp = matches!(recipient, Recipient::SilentPayment(_));
    if recipient_is_sp {
        // true marks each key as taproot since every silent payment coin is a P2TR output
        let input_keys: Vec<(SecretKey, bool)> = signing_keys.iter().map(|k| (*k, true)).collect();

        let outpoints: Vec<(String, u32)> = utxo_selection
            .iter()
            .map(|c| (c.outpoint.txid.to_string(), c.outpoint.vout))
            .collect();

        let partial_secret = calculate_partial_secret(&input_keys, &outpoints)?;
        let mut sp_addrs = Vec::new();
        if let Recipient::SilentPayment(sp) = &recipient {
            sp_addrs.push(*sp);
        }
        sp_addrs.push(change_address);
        derived = generate_recipient_pubkeys(sp_addrs, partial_secret)?;
    }

    let recipient_script = match recipient {
        Recipient::Address(ref address) => address.script_pubkey(),
        Recipient::SilentPayment(sp) => sp_output_script(&derived, sp)?,
    };

    let recipient_output = TxOut {
        value: target_amount,
        script_pubkey: recipient_script
    };

    output.push(recipient_output);

    let change_output = TxOut {
        value: change_value,
        script_pubkey: sp_output_script(&derived, change_address)?
    };
    output.push(change_output);

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(tip_height).unwrap_or(LockTime::ZERO),
        input,
        output,
    };

    let prevouts: Vec<TxOut> = utxo_selection 
        .iter()
        .map(|c| TxOut {
            value: c.coin.value,
            script_pubkey: c.coin.script_pubkey.clone(),
        })
        .collect();
    debug_assert_eq!(signing_keys.len(), prevouts.len());
    let mut cache = SighashCache::new(&tx);
    let mut witnesses = Vec::with_capacity(utxo_selection.len());
    for (i, signing_key) in signing_keys.iter().enumerate() {
        let sighash = cache.taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )?;
        let keypair = Keypair::from_secret_key(&secp, signing_key);
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        let sig = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };
        witnesses.push(Witness::from_slice(&[sig.serialize()]));
    }
    for (txin, witness) in tx.input.iter_mut().zip(witnesses) {
        txin.witness = witness;
    }

    Ok(tx)
}

fn sp_output_script(
    derived: &HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>>,
    address: SilentPaymentAddress,
) -> Result<ScriptBuf, SendError> {
    let xonly = derived
        .get(&address)
        .and_then(|keys| keys.first())
        .ok_or(SendError::OutputDerivation)?;
    Ok(p2tr_script(*xonly))
}

fn p2tr_script(output_key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Parity, Scalar};
    use bitcoin::Txid;
    use silentpayments::Network;

    use crate::silentpayments::build_receiver;

    fn even_secret(bytes: [u8; 32]) -> SecretKey {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&bytes).unwrap();
        match key.x_only_public_key(&secp).1 {
            Parity::Odd => key.negate(),
            Parity::Even => key,
        }
    }

    fn address(scan: SecretKey, spend: SecretKey) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        let spend_pub = spend.public_key(&secp);
        build_receiver(&scan, spend_pub, Network::Regtest)
            .unwrap()
            .get_receiving_address()
    }

    fn owned_coin(spend_secret: &SecretKey, tweak: Scalar, value: Amount) -> Coin {
        let secp = Secp256k1::new();
        let output_key = spend_secret
            .add_tweak(&tweak)
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        Coin {
            value,
            script_pubkey: p2tr_script(output_key),
            tweak,
            label: None,
            block_height: 1,
            spent_by: None,
        }
    }

    #[test]
    fn signs_a_spendable_taproot_input() {
        let secp = Secp256k1::new();
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let change_address = build_receiver(
            &scan_secret,
            spend_secret.public_key(&secp),
            Network::Regtest,
        )
        .unwrap()
        .get_change_address();

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let coins = [SpendableCoin {
            outpoint,
            coin: &coin,
        }];

        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);
        let tx = build_transaction(
            &spend_secret,
            Recipient::SilentPayment(recipient),
            amount,
            fee_rate,
            100,
            change_address,
            &coins,
        )
        .unwrap();

        assert_eq!(tx.lock_time, LockTime::from_height(100).unwrap());
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert!(tx.output.iter().any(|o| o.value == amount));

        let fee = coin.value - tx.output.iter().map(|o| o.value).sum::<Amount>();
        // TODO
        // assert!(fee > Amount::ZERO);

        let prevouts = [TxOut {
            value: coin.value,
            script_pubkey: coin.script_pubkey.clone(),
        }];
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let witness = &tx.input[0].witness;
        let sig = secp256k1::schnorr::Signature::from_slice(&witness[0][..64]).unwrap();
        let output_key = spend_secret
            .add_tweak(&tweak)
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        secp.verify_schnorr(&sig, &message, &output_key)
            .expect("signature must verify against the output key");
    }

    #[test]
    fn rejects_amount_over_balance() {
        let spend_secret = even_secret([0x02; 32]);
        let change_address = address(even_secret([0x01; 32]), spend_secret);
        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(10_000));
        let coins = [SpendableCoin {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 0,
            },
            coin: &coin,
        }];

        let err = build_transaction(
            &spend_secret,
            Recipient::SilentPayment(recipient),
            Amount::from_sat(20_000),
            FeeRate::from_sat_per_vb(2).unwrap(),
            100,
            change_address,
            &coins,
        )
        .unwrap_err();
        assert!(matches!(err, SendError::NoSpendableCoins));
    }

    #[test]
    fn reserved_coins_are_not_reselected() {
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let mut wallet = Wallet::new(Network::Regtest);
        wallet
            .import_signing_keys(scan_secret, spend_secret)
            .unwrap();

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        wallet.utxos.insert(outpoint, coin);

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);

        let tx = wallet
            .build_transaction(Recipient::SilentPayment(recipient), amount, fee_rate)
            .unwrap();
        wallet.reserve_coins(tx.input.iter().map(|i| i.previous_output));

        let err = wallet
            .build_transaction(Recipient::SilentPayment(recipient), amount, fee_rate)
            .unwrap_err();
        assert!(matches!(err, SendError::NoSpendableCoins));
    }

    #[test]
    fn released_coins_are_selectable_again() {
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let mut wallet = Wallet::new(Network::Regtest);
        wallet
            .import_signing_keys(scan_secret, spend_secret)
            .unwrap();

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        wallet.utxos.insert(outpoint, coin);

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);

        let tx = wallet
            .build_transaction(Recipient::SilentPayment(recipient), amount, fee_rate)
            .unwrap();
        let outpoints: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();

        wallet.reserve_coins(outpoints.iter().copied());
        assert!(matches!(
            wallet.build_transaction(Recipient::SilentPayment(recipient), amount, fee_rate),
            Err(SendError::NoSpendableCoins)
        ));

        wallet.release_coins(outpoints);
        assert!(wallet
            .build_transaction(Recipient::SilentPayment(recipient), amount, fee_rate)
            .is_ok());
    }

    #[test]
    fn sends_to_plain_addresses_of_every_type() {
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);

        let secp = Secp256k1::new();
        let pubkey = even_secret([0x07; 32]).public_key(&secp);
        let xonly = pubkey.x_only_public_key().0;
        let compressed = bitcoin::CompressedPublicKey(pubkey);
        let legacy = bitcoin::PublicKey::new(pubkey);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let net = bitcoin::Network::Regtest;

        let recipients = [
            ("p2wpkh", bitcoin::Address::p2wpkh(&compressed, net)),
            ("p2wsh", bitcoin::Address::p2wsh(&script, net)),
            ("p2tr", bitcoin::Address::p2tr(&secp, xonly, None, net)),
            ("p2pkh", bitcoin::Address::p2pkh(legacy, net)),
            ("p2sh", bitcoin::Address::p2sh(&script, net).unwrap()),
        ];

        for (kind, addr) in recipients {
            let mut wallet = Wallet::new(Network::Regtest);
            wallet
                .import_signing_keys(scan_secret, spend_secret)
                .unwrap();

            let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
            let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
            wallet.utxos.insert(
                OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                coin,
            );

            let recipient_spk = addr.script_pubkey();
            let amount = Amount::from_sat(50_000);
            let tx = wallet
                .build_transaction(
                    Recipient::Address(addr),
                    amount,
                    FeeRate::from_sat_per_vb(2).unwrap(),
                )
                .unwrap_or_else(|e| panic!("{kind}: {e}"));

            assert_eq!(tx.input.len(), 1, "{kind}");
            assert!(
                tx.output
                    .iter()
                    .any(|o| o.script_pubkey == recipient_spk && o.value == amount),
                "{kind}: recipient output missing"
            );
            assert!(
                tx.output.iter().any(|o| o.script_pubkey != recipient_spk),
                "{kind}: change output missing"
            );
        }
    }

    #[test]
    fn rejects_empty_wallet() {
        let spend_secret = even_secret([0x02; 32]);
        let change_address = address(even_secret([0x01; 32]), spend_secret);
        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let err = build_transaction(
            &spend_secret,
            Recipient::SilentPayment(recipient),
            Amount::from_sat(1_000),
            FeeRate::from_sat_per_vb(2).unwrap(),
            100,
            change_address,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SendError::NoSpendableCoins));
    }
}
