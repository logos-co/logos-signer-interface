//! A mock that answers wrong, in each way a device could: the checks the manager runs refuse
//! every one, and the right answer still passes them.

use logos_signer_interface::mock::{Doctor, MockOptions, MockSigner};
use logos_signer_interface::verify::check;
use logos_signer_interface::*;

/// One item per account, in the scheme its family signs with.
fn items_for(account: &Account) -> Vec<HashItem> {
    let (scheme, path) = match account.family {
        Family::Evm => (Scheme::Evm, None),
        Family::Bitcoin => (Scheme::Ecdsa, Some(format!("{}/0/0", account.path.as_deref().unwrap()))),
        Family::BitcoinTaproot => (Scheme::Bip86, Some(format!("{}/0/1", account.path.as_deref().unwrap()))),
    };
    vec![
        HashItem {
            path: path.clone(),
            scheme,
            digest: "11".repeat(32),
        },
        HashItem {
            path,
            scheme,
            digest: "22".repeat(32),
        },
    ]
}

/// Every account's answer under `doctor`: `(account, items, signatures)`.
fn answers(doctor: Doctor) -> Vec<(Account, Vec<HashItem>, Vec<Signature>)> {
    let mut s = MockSigner::new(MockOptions {
        doctor,
        ..Default::default()
    });
    s.accounts()
        .unwrap()
        .into_iter()
        .map(|account| {
            let items = items_for(&account);
            let req = SignRequest {
                account: account.id.clone(),
                payload: Payload::Hash { items: items.clone() },
                secret: None,
                xpub: None,
            };
            let job = s.sign(req).unwrap();
            let sigs = s.result(&job).unwrap();
            (account, items, sigs)
        })
        .collect()
}

#[test]
fn the_right_answer_passes_the_checks() {
    for (account, items, sigs) in answers(Doctor::None) {
        assert_eq!(sigs.len(), items.len(), "{}", account.id);
        for (item, sig) in items.iter().zip(&sigs) {
            check(&account, item, sig).unwrap_or_else(|e| panic!("{}: {e}", account.id));
        }
    }
}

#[test]
fn a_signature_by_another_key_is_refused() {
    for (account, items, sigs) in answers(Doctor::OtherKey) {
        for (item, sig) in items.iter().zip(&sigs) {
            assert!(
                check(&account, item, sig).is_err(),
                "{} took another key's signature",
                account.id
            );
        }
    }
}

#[test]
fn a_signature_over_another_digest_is_refused() {
    for (account, items, sigs) in answers(Doctor::OtherDigest) {
        for (item, sig) in items.iter().zip(&sigs) {
            assert!(
                check(&account, item, sig).is_err(),
                "{} took a signature over another digest",
                account.id
            );
        }
    }
}

#[test]
fn an_answer_one_signature_short_is_short() {
    for (account, items, sigs) in answers(Doctor::DropLast) {
        assert_eq!(sigs.len(), items.len() - 1, "{}", account.id);
    }
}

#[test]
fn another_phrase_makes_other_accounts_and_unplugging_keeps_them_listed() {
    let ours = MockSigner::new(MockOptions::default()).accounts().unwrap();
    let mut other = MockSigner::new(MockOptions {
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        ..Default::default()
    });
    let theirs = other.accounts().unwrap();
    assert_ne!(ours[0].id, theirs[0].id, "another phrase, another EVM address");
    other.set_available(false);
    let unplugged = other.accounts().unwrap();
    assert_eq!(unplugged.len(), theirs.len());
    assert!(unplugged.iter().all(|a| !a.available));
}

#[test]
fn the_names_parse() {
    for (name, want) in [
        ("none", Doctor::None),
        ("other_key", Doctor::OtherKey),
        ("other_digest", Doctor::OtherDigest),
        ("drop_last", Doctor::DropLast),
    ] {
        assert_eq!(Doctor::parse(name), Some(want));
    }
    assert_eq!(Doctor::parse("sometimes"), None);
}
