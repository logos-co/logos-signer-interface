//! Whole requests, as a device with a screen takes them: the mock works out each digest itself,
//! and the manager's check passes its answer over the digest worked out here, apart from it.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, CompressedPublicKey, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};

use logos_signer_interface::mock::{Doctor, MockOptions, MockSigner};
use logos_signer_interface::verify::{check, derive};
use logos_signer_interface::*;

const WHOLE: [RequestKind; 4] = [
    RequestKind::EvmTransaction,
    RequestKind::EvmMessage,
    RequestKind::EvmTypedData,
    RequestKind::BtcPsbt,
];

fn device(doctor: Doctor) -> (MockSigner, Vec<Account>) {
    let mut s = MockSigner::new(MockOptions {
        request_kinds: WHOLE.to_vec(),
        doctor,
        ..Default::default()
    });
    let accounts = s.accounts().unwrap();
    (s, accounts)
}

fn sign(s: &mut MockSigner, account: &Account, payload: Payload) -> Result<Vec<Signature>> {
    let job = s.sign(SignRequest {
        account: account.id.clone(),
        payload,
        secret: None,
        xpub: None,
    })?;
    s.result(&job)
}

fn evm_item(data: &[u8]) -> HashItem {
    HashItem {
        path: None,
        scheme: Scheme::Evm,
        digest: hex::encode(Keccak256::digest(data)),
    }
}

/// A one-input PSBT spending `script` from `account`'s key at `path`, with that key's origin.
fn psbt_for(account: &Account, path: &str, fingerprint: &str) -> (Psbt, TxOut, SecpPublicKey) {
    let key = derive(account.xpub.as_deref().unwrap(), account.path.as_deref().unwrap(), path).unwrap();
    let key = SecpPublicKey::from_slice(key.to_encoded_point(true).as_bytes()).unwrap();
    let secp = Secp256k1::verification_only();
    let script = match account.family {
        Family::Bitcoin => ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash()),
        _ => ScriptBuf::new_p2tr(&secp, key.x_only_public_key().0, None),
    };
    let prev = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: script,
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::from_str("1111111111111111111111111111111111111111111111111111111111111111:0")
                .unwrap(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: prev.script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let origin = (
        Fingerprint::from_str(fingerprint).unwrap(),
        DerivationPath::from_str(path).unwrap(),
    );
    psbt.inputs[0].witness_utxo = Some(prev.clone());
    match account.family {
        Family::Bitcoin => {
            psbt.inputs[0].bip32_derivation.insert(key, origin);
        }
        _ => {
            psbt.inputs[0]
                .tap_key_origins
                .insert(key.x_only_public_key().0, (vec![], origin));
        }
    }
    (psbt, prev, key)
}

#[test]
fn an_evm_transaction_is_signed_over_its_own_hash() {
    let (mut s, accounts) = device(Doctor::None);
    let tx = hex::decode("02e80180843b9aca00847735940082520894000000000000000000000000000000000000dead0180c0").unwrap();
    let sigs = sign(
        &mut s,
        &accounts[0],
        Payload::EvmTransaction {
            chain_id: 1,
            tx: hex::encode(&tx),
        },
    )
    .unwrap();
    assert_eq!(sigs.len(), 1);
    check(&accounts[0], &evm_item(&tx), &sigs[0]).unwrap();
}

#[test]
fn a_message_is_signed_as_personal_sign() {
    let (mut s, accounts) = device(Doctor::None);
    let sigs = sign(
        &mut s,
        &accounts[0],
        Payload::EvmMessage {
            message: hex::encode("hello device"),
        },
    )
    .unwrap();
    check(
        &accounts[0],
        &evm_item(b"\x19Ethereum Signed Message:\n12hello device"),
        &sigs[0],
    )
    .unwrap();
}

#[test]
fn psbt_inputs_are_signed_over_their_sighashes() {
    let (mut s, accounts) = device(Doctor::None);
    for account in &accounts[1..] {
        let fp = account.fingerprint.clone().unwrap();
        let path = format!("{}/0/3", account.path.as_deref().unwrap());
        let (psbt, prev, _) = psbt_for(account, &path, &fp);
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let item = match account.family {
            Family::Bitcoin => HashItem {
                path: Some(path.clone()),
                scheme: Scheme::Ecdsa,
                digest: hex::encode(
                    cache
                        .p2wpkh_signature_hash(0, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
                        .unwrap()
                        .to_byte_array(),
                ),
            },
            _ => HashItem {
                path: Some(path.clone()),
                scheme: Scheme::Bip86,
                digest: hex::encode(
                    cache
                        .taproot_key_spend_signature_hash(
                            0,
                            &Prevouts::All(std::slice::from_ref(&prev)),
                            TapSighashType::Default,
                        )
                        .unwrap()
                        .to_byte_array(),
                ),
            },
        };
        let sigs = sign(
            &mut s,
            account,
            Payload::BtcPsbt {
                network: "regtest".into(),
                psbt: psbt.to_string(),
            },
        )
        .unwrap();
        assert_eq!(sigs.len(), 1, "{}", account.id);
        assert_eq!(sigs[0].item, 0, "{}: the input it signs", account.id);
        check(account, &item, &sigs[0]).unwrap_or_else(|e| panic!("{}: {e}", account.id));
    }
}

#[test]
fn a_psbt_naming_another_wallets_key_is_invalid() {
    let (mut s, accounts) = device(Doctor::None);
    let account = &accounts[1];
    let path = format!("{}/0/0", account.path.as_deref().unwrap());
    let (psbt, _, _) = psbt_for(account, &path, "deadbeef");
    let e = sign(
        &mut s,
        account,
        Payload::BtcPsbt {
            network: "regtest".into(),
            psbt: psbt.to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{e:?}");
}

#[test]
fn typed_data_stays_a_hash_for_the_mock() {
    let (mut s, accounts) = device(Doctor::None);
    let e = sign(
        &mut s,
        &accounts[0],
        Payload::EvmTypedData {
            typed_data: serde_json::json!({}),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
}

#[test]
fn a_doctored_answer_to_a_whole_request_is_refused() {
    let tx = b"\x02\xc0";
    for doctor in [Doctor::OtherKey, Doctor::OtherDigest] {
        let (mut s, accounts) = device(doctor);
        let sigs = sign(
            &mut s,
            &accounts[0],
            Payload::EvmTransaction {
                chain_id: 1,
                tx: hex::encode(tx),
            },
        )
        .unwrap();
        assert!(check(&accounts[0], &evm_item(tx), &sigs[0]).is_err(), "{doctor:?}");
    }
}

#[test]
fn a_hash_request_is_unsupported_by_a_whole_request_signer() {
    let (mut s, accounts) = device(Doctor::None);
    let e = sign(
        &mut s,
        &accounts[0],
        Payload::Hash {
            items: vec![evm_item(b"x")],
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
}

#[test]
fn what_it_takes_can_change_while_it_runs() {
    let mut s = MockSigner::new(MockOptions::default());
    let accounts = s.accounts().unwrap();
    let message = || Payload::EvmMessage {
        message: hex::encode("now whole"),
    };
    assert_eq!(
        sign(&mut s, &accounts[0], message()).unwrap_err().code,
        ErrorCode::Unsupported
    );
    s.set_request_kinds(WHOLE.to_vec());
    assert_eq!(s.info().request_kinds, WHOLE.to_vec());
    assert_eq!(sign(&mut s, &accounts[0], message()).unwrap().len(), 1);
}

#[test]
fn a_taproot_input_names_its_internal_key() {
    let mut m = MockSigner::new(MockOptions::default());
    let account = m
        .accounts()
        .unwrap()
        .into_iter()
        .find(|a| a.family == Family::BitcoinTaproot)
        .unwrap();
    let base = account.path.clone().unwrap();
    let path = format!("{base}/0/0");
    let (psbt, _) = conformance::psbt_for(&account, &[(path.clone(), path)]);
    let psbt = bitcoin::Psbt::from_str(&psbt).unwrap();
    let origin = psbt.inputs[0].tap_key_origins.keys().next().copied();
    assert!(origin.is_some());
    assert_eq!(
        psbt.inputs[0].tap_internal_key, origin,
        "as wallets write a key-path spend"
    );
}
