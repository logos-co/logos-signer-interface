use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::json;
use logos_signer_interface::mock::{MockOptions, MockSigner};
use logos_signer_interface::*;

fn no_device(_: &mut MockSigner, _: &str) {}

#[test]
fn a_signer_without_a_secret_passes() {
    let mut s = MockSigner::new(MockOptions::default());
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut no_device,
    );
}

#[test]
fn a_signer_with_a_password_passes() {
    let mut s = MockSigner::new(MockOptions {
        collects: Collects::Password,
        secret: "pw".into(),
        ..Default::default()
    });
    let fx = Fixture {
        secret: Some(Secret::new("pw")),
        wrong_secret: Some(Secret::new("nope")),
    };
    conformance::run(&mut s, &fx, &mut no_device);
}

#[test]
fn a_signer_that_waits_for_its_device_passes() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        request_kinds: vec![RequestKind::Hash, RequestKind::EvmMessage],
        ..Default::default()
    });
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut |s, job| s.confirm(job).unwrap(),
    );
}

#[test]
fn a_device_that_signs_whole_requests_passes() {
    for kinds in [
        vec![RequestKind::EvmTransaction, RequestKind::BtcPsbt],
        vec![RequestKind::EvmMessage, RequestKind::BtcPsbt],
    ] {
        let mut s = MockSigner::new(MockOptions {
            needs_confirmation: true,
            request_kinds: kinds,
            ..Default::default()
        });
        conformance::run(
            &mut s,
            &Fixture {
                secret: None,
                wrong_secret: None,
            },
            &mut |s, job| s.confirm(job).unwrap(),
        );
    }
}

#[test]
fn the_suites_transaction_is_canonical_rlp() {
    // Worked by hand in EIP-1559's field order: a 47-byte list after the type byte.
    let want = [
        "02ef",                                       // type 2, list of 47 bytes
        "01",                                         // chain id 1
        "07",                                         // nonce 7
        "843b9aca00",                                 // priority fee, 1 gwei
        "8506fc23ac00",                               // max fee, 30 gwei
        "825208",                                     // gas 21000
        "94dddddddddddddddddddddddddddddddddddddddd", // to
        "87038d7ea4c68000",                           // 0.001 ether
        "80",                                         // no data
        "c0",                                         // no access list
    ]
    .concat();
    assert_eq!(hex::encode(conformance::eip1559(7)), want);
}

#[test]
fn a_refusal_on_the_device_is_a_refused_job_with_no_signatures() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        ..Default::default()
    });
    let account = s.accounts().unwrap().remove(0);
    let req = SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&account),
        },
        secret: None,
        xpub: None,
    };
    let job = s.sign(req).unwrap();
    assert_eq!(s.status(&job).unwrap().state, JobState::ConfirmOnDevice);
    s.refuse(&job).unwrap();
    assert_eq!(s.status(&job).unwrap().state, JobState::Refused);
    assert_eq!(s.result(&job).unwrap_err().code, ErrorCode::Refused);
}

#[test]
fn a_cancelled_job_never_signs() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        ..Default::default()
    });
    let account = s.accounts().unwrap().remove(0);
    let req = SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&account),
        },
        secret: None,
        xpub: None,
    };
    let job = s.sign(req).unwrap();
    s.cancel(&job).unwrap();
    assert!(s.confirm(&job).is_err());
    assert_eq!(s.status(&job).unwrap().state, JobState::Cancelled);
}

#[test]
fn the_json_replies_read_back_as_they_were_written() {
    let mut s = MockSigner::new(MockOptions {
        collects: Collects::Pin,
        secret: "123456".into(),
        ..Default::default()
    });
    let info = json::read_info(&json::signer_info(&s)).unwrap();
    assert_eq!(info, s.info());
    let accounts = json::read_accounts(&json::signer_accounts(&mut s)).unwrap();
    assert_eq!(accounts.len(), 3);

    let bad = json::sign(
        &mut s,
        &serde_json::json!({ "account": accounts[0].id, "kind": "hash", "items": [] }).to_string(),
    );
    assert_eq!(json::read_job(&bad).unwrap_err().code, ErrorCode::Locked);

    let req = SignRequest {
        account: accounts[1].id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&accounts[1]),
        },
        secret: Some(Secret::new("123456")),
        xpub: None,
    };
    let job = json::read_job(&json::sign(&mut s, &serde_json::to_string(&req).unwrap())).unwrap();
    let status = json::read_status(&json::sign_status(&mut s, &job)).unwrap();
    assert_eq!(status.state, JobState::Done);
    let sigs = json::read_signatures(&json::sign_result(&mut s, &job)).unwrap();
    assert_eq!(sigs.len(), 2);

    let unknown = json::read_status(&json::sign_status(&mut s, "job_0"));
    assert_eq!(unknown.unwrap_err().code, ErrorCode::UnknownJob);
}

#[test]
fn a_failed_job_reports_its_code_beside_its_state() {
    let st = JobStatus {
        job: "job_1".into(),
        state: JobState::Failed,
        error: Some(SignerError::new(ErrorCode::WrongSecret, "wrong password")),
    };
    let v = serde_json::to_value(&st).unwrap();
    assert_eq!(v["code"], "wrong_secret");
    assert_eq!(v["state"], "failed");
    let back: JobStatus = serde_json::from_value(v).unwrap();
    assert_eq!(back, st);
}

#[test]
fn a_secret_never_prints() {
    let s = Secret::new("hunter2");
    assert_eq!(format!("{s:?}"), "Secret(..)");
    let req = SignRequest {
        account: "a".into(),
        payload: Payload::Hash { items: vec![] },
        secret: Some(s),
        xpub: None,
    };
    assert!(!format!("{req:?}").contains("hunter2"));
}

#[test]
fn the_mock_evm_account_is_the_well_known_first_test_account() {
    let mut s = MockSigner::new(MockOptions::default());
    let evm = s.accounts().unwrap().remove(0);
    assert_eq!(
        evm.address.as_deref(),
        Some("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
    );
}

#[test]
fn check_refuses_a_signature_over_another_digest_or_by_another_account() {
    let mut s = MockSigner::new(MockOptions::default());
    let accounts = s.accounts().unwrap();
    for account in &accounts {
        let items = conformance::items_for(account);
        let req = SignRequest {
            account: account.id.clone(),
            payload: Payload::Hash { items: items.clone() },
            secret: None,
            xpub: None,
        };
        let job = s.sign(req).unwrap();
        let sig = s.result(&job).unwrap().remove(0);
        verify::check(account, &items[0], &sig).unwrap();

        let mut other_digest = items[0].clone();
        other_digest.digest = conformance::items_for(account)[0].digest.clone();
        assert!(
            verify::check(account, &other_digest, &sig).is_err(),
            "{}: another digest",
            account.id
        );

        let stranger = accounts
            .iter()
            .find(|a| a.family == account.family && a.id != account.id);
        if let Some(stranger) = stranger {
            assert!(verify::check(stranger, &items[0], &sig).is_err());
        }
        if account.family.is_bitcoin() {
            let mut other_key = items[0].clone();
            other_key.path = items.get(1).and_then(|i| i.path.clone());
            assert!(
                verify::check(account, &other_key, &sig).is_err(),
                "{}: another key",
                account.id
            );
        }
    }
}

fn unlock_key(s: &mut MockSigner, seed: &str, index: u32) -> Result<Secret> {
    let job = s.unlock_key(UnlockKeyRequest {
        seed: seed.into(),
        index,
        secret: None,
    })?;
    Ok(s.unlock_key_result(&job)?.key)
}

fn seed_of(s: &mut MockSigner) -> String {
    s.accounts().unwrap()[0].seed.clone().unwrap()
}

#[test]
fn every_holder_of_a_seed_gives_the_same_unlock_key() {
    let mut keystore = MockSigner::new(MockOptions::default());
    let mut device = MockSigner::new(MockOptions {
        kind: "keycard".into(),
        ..Default::default()
    });
    let mut other = MockSigner::new(MockOptions {
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        ..Default::default()
    });
    let seed = seed_of(&mut keystore);
    assert_eq!(seed_of(&mut device), seed);
    assert!(keystore
        .accounts()
        .unwrap()
        .iter()
        .all(|a| a.seed.as_deref() == Some(seed.as_str())));
    let one = unlock_key(&mut keystore, &seed, 0).unwrap();
    assert_eq!(unlock_key(&mut device, &seed, 0).unwrap(), one);
    assert_ne!(unlock_key(&mut keystore, &seed, 1).unwrap(), one);

    let theirs = seed_of(&mut other);
    assert_ne!(theirs, seed);
    assert_ne!(unlock_key(&mut other, &theirs, 0).unwrap(), one);
    assert_eq!(unlock_key(&mut other, &seed, 0).unwrap_err().code, ErrorCode::WrongSeed);
}

#[test]
fn the_unlock_key_is_the_public_key_at_the_unlock_path() {
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use bitcoin::secp256k1::Secp256k1;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(mock::PHRASE.as_bytes(), b"mnemonic", 2048, &mut seed);
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &seed).unwrap();
    let at = master
        .derive_priv(&secp, &DerivationPath::from_str("m/1280263247'/0'").unwrap())
        .unwrap();
    let expected = hex::encode(Xpub::from_priv(&secp, &at).public_key.serialize());

    let mut s = MockSigner::new(MockOptions::default());
    let named = hex::encode(Sha256::digest(
        Xpub::from_priv(&secp, &master).public_key.serialize_uncompressed(),
    ));
    assert_eq!(seed_of(&mut s), named, "a seed is named as a Keycard names it");
    assert_eq!(unlock_key(&mut s, &named, 0).unwrap().expose(), expected);
}

#[test]
fn an_unplugged_device_gives_no_unlock_key() {
    let mut s = MockSigner::new(MockOptions {
        available: false,
        ..Default::default()
    });
    let seed = seed_of(&mut s);
    assert_eq!(unlock_key(&mut s, &seed, 0).unwrap_err().code, ErrorCode::Unavailable);
}

#[test]
fn an_unlock_key_reads_once_over_json() {
    let mut s = MockSigner::new(MockOptions::default());
    let seed = seed_of(&mut s);
    let job = json::read_job(&json::unlock_key(&mut s, &format!(r#"{{"seed":"{seed}","index":0}}"#))).unwrap();
    let key = json::read_unlock_key(&json::unlock_key_result(&mut s, &job)).unwrap();
    assert_eq!(key.key.expose().len(), 66);
    assert!(json::read_unlock_key(&json::unlock_key_result(&mut s, &job)).is_err());
    let foreign = json::read_job(&json::unlock_key(
        &mut s,
        &format!(r#"{{"seed":"{}"}}"#, "0".repeat(64)),
    ));
    assert_eq!(foreign.unwrap_err().code, ErrorCode::WrongSeed);
    let past = json::read_job(&json::unlock_key(
        &mut s,
        &format!(r#"{{"seed":"{seed}","index":2147483648}}"#),
    ));
    assert!(past.is_err());
}

#[test]
fn the_roster_key_is_the_one_the_manager_computes() {
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    let mut s = MockSigner::new(MockOptions::default());
    for a in s.accounts().unwrap().into_iter().filter(|a| a.family.is_bitcoin()) {
        let xpub = bitcoin::bip32::Xpub::from_str(a.xpub.as_deref().unwrap()).unwrap();
        let mut h = Sha256::new();
        h.update(serde_json::to_string(&a.family).unwrap().as_bytes());
        h.update(serde_json::to_string(&a.chain).unwrap().as_bytes());
        h.update(xpub.chain_code.as_bytes());
        h.update(xpub.public_key.serialize());
        let manager = format!("btc_{}", hex::encode(&h.finalize()[..16]));
        assert_eq!(a.key.as_deref(), Some(manager.as_str()), "{}", a.id);
    }
}

#[test]
fn nothing_signs_under_the_reserved_purpose() {
    let mut s = MockSigner::new(MockOptions::default());
    let req = SignRequest {
        account: "mock-segwit".into(),
        payload: Payload::Hash {
            items: vec![HashItem {
                path: Some("m/1280263247'/0'".into()),
                scheme: Scheme::Ecdsa,
                digest: "00".repeat(32),
            }],
        },
        secret: None,
        xpub: None,
    };
    assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Invalid);
}
