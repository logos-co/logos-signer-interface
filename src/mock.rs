//! A signer with software keys behind the interface: an EVM account, a native segwit and a taproot
//! account from the "test … junk" phrase or another. Optionally it asks for a secret, holds every
//! job until [`MockSigner::confirm`] the way a device waits for its button, or answers wrong.
//! Given whole requests, it works out their digests itself, as a device with a screen does.

use std::str::FromStr;

use bip32::{ChildNumber, DerivationPath, Prefix, XPrv};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{schnorr, PublicKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use crate::jobs::{JobTable, KeyJobs};
use crate::unlock::{check_xpub, is_reserved, roster_key, unlock_key_path};
use crate::verify::{bip86_tweak, evm_address, hex32, relative};
use crate::wire::*;
use crate::{Signer, INTERFACE};

pub const PHRASE: &str = "test test test test test test test test test test test junk";

/// How a mock answers: rightly, or wrong in one of the ways the manager must refuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Doctor {
    #[default]
    None,
    /// A valid signature, by another key.
    OtherKey,
    /// A valid signature, over another digest.
    OtherDigest,
    /// One signature fewer than the items asked for.
    DropLast,
}

impl Doctor {
    pub fn parse(s: &str) -> Option<Doctor> {
        Some(match s {
            "none" => Doctor::None,
            "other_key" => Doctor::OtherKey,
            "other_digest" => Doctor::OtherDigest,
            "drop_last" => Doctor::DropLast,
            _ => return None,
        })
    }
}

#[derive(Clone)]
pub struct MockOptions {
    pub collects: Collects,
    /// The secret it accepts when `collects` asks for one.
    pub secret: String,
    /// Jobs wait in `confirm_on_device` until confirmed or refused.
    pub needs_confirmation: bool,
    pub request_kinds: Vec<RequestKind>,
    /// The words its keys come from; another phrase keeps it apart from a keystore's test keys.
    pub phrase: String,
    pub doctor: Doctor,
    /// `signer_info`'s kind: another signer's, to stand in for it beside a real one.
    pub kind: String,
    /// Whether its "device" starts plugged in.
    pub available: bool,
}

impl Default for MockOptions {
    fn default() -> Self {
        MockOptions {
            collects: Collects::Nothing,
            secret: String::new(),
            needs_confirmation: false,
            request_kinds: vec![RequestKind::Hash],
            phrase: PHRASE.into(),
            doctor: Doctor::None,
            kind: "mock".into(),
            available: true,
        }
    }
}

struct Held {
    account: Account,
    key: XPrv,
}

pub struct MockSigner {
    opts: MockOptions,
    seed: [u8; 64],
    recogniser: String,
    accounts: Vec<Held>,
    jobs: JobTable,
    waiting: Vec<(String, SignRequest)>,
    keys: KeyJobs,
    waiting_keys: Vec<(String, UnlockKeyRequest)>,
}

fn fingerprint(master: &XPrv) -> String {
    hex::encode(master.public_key().fingerprint())
}

/// How it names its seed, as a Keycard does: the SHA-256 of the uncompressed master public key.
fn recogniser(master: &XPrv) -> String {
    let point = master.public_key().public_key().to_encoded_point(false);
    hex::encode(Sha256::digest(point.as_bytes()))
}

impl MockSigner {
    pub fn new(opts: MockOptions) -> Self {
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(opts.phrase.as_bytes(), b"mnemonic", 2048, &mut seed);
        let master = XPrv::new(seed).expect("master");
        let fp = fingerprint(&master);
        let seed_id = recogniser(&master);
        let derive = |p: &str| XPrv::derive_from_path(seed, &DerivationPath::from_str(p).unwrap()).unwrap();

        let evm = derive("m/44'/60'/0'/0/0");
        let address = evm_address(&PublicKey::from(evm.public_key().public_key()));
        let mut accounts = vec![Held {
            account: Account {
                id: address.clone(),
                family: Family::Evm,
                chain: None,
                path: Some("m/44'/60'/0'/0/0".into()),
                fingerprint: Some(fp.clone()),
                address: Some(address),
                xpub: None,
                key: None,
                seed: Some(seed_id.clone()),
                label: Some("Mock EVM".into()),
                available: true,
            },
            key: evm,
        }];
        for (id, family, path, label) in [
            ("mock-segwit", Family::Bitcoin, "m/84'/1'/0'", "Mock native segwit"),
            ("mock-taproot", Family::BitcoinTaproot, "m/86'/1'/0'", "Mock taproot"),
        ] {
            let key = derive(path);
            let xpub = key.public_key().to_string(Prefix::TPUB);
            accounts.push(Held {
                account: Account {
                    id: id.into(),
                    family,
                    chain: Some(Chain::Test),
                    path: Some(path.into()),
                    fingerprint: Some(fp.clone()),
                    address: None,
                    key: roster_key(family, Some(Chain::Test), &xpub).ok(),
                    xpub: Some(xpub),
                    seed: Some(seed_id.clone()),
                    label: Some(label.into()),
                    available: true,
                },
                key,
            });
        }
        let available = opts.available;
        let mut s = MockSigner {
            opts,
            seed,
            recogniser: seed_id,
            accounts,
            jobs: JobTable::new(),
            waiting: Vec::new(),
            keys: KeyJobs::new(),
            waiting_keys: Vec::new(),
        };
        s.set_available(available);
        s
    }

    /// Answer wrong from now on, or rightly again.
    pub fn set_doctor(&mut self, doctor: Doctor) {
        self.opts.doctor = doctor;
    }

    /// What it takes from now on: hashes, or whole requests as a device with a screen does.
    pub fn set_request_kinds(&mut self, kinds: Vec<RequestKind>) {
        self.opts.request_kinds = kinds;
    }

    /// The "device" is plugged in or not: its accounts stay listed, available or not.
    pub fn set_available(&mut self, available: bool) {
        for h in &mut self.accounts {
            h.account.available = available;
        }
    }

    /// Jobs waiting for the person, with what each asks to sign.
    pub fn waiting(&self) -> Vec<(String, SignRequest)> {
        self.waiting.clone()
    }

    /// Unlock-key jobs waiting for the person.
    pub fn waiting_keys(&self) -> Vec<String> {
        self.waiting_keys.iter().map(|(j, _)| j.clone()).collect()
    }

    /// The person confirms on the "device": a signature or an unlock key.
    pub fn confirm(&mut self, job: &str) -> Result<()> {
        if let Some(at) = self.waiting_keys.iter().position(|(j, _)| j == job) {
            let (_, request) = self.waiting_keys.remove(at);
            let outcome = self.key_now(&request);
            return self.keys.finish(job, outcome);
        }
        let at = self.waiting.iter().position(|(j, _)| j == job);
        let Some(at) = at else {
            return Err(SignerError::new(ErrorCode::UnknownJob, job));
        };
        let (_, request) = self.waiting.remove(at);
        let outcome = self.sign_now(&request);
        self.jobs.finish(job, outcome)
    }

    /// The person declines on the "device".
    pub fn refuse(&mut self, job: &str) -> Result<()> {
        let declined = || SignerError::new(ErrorCode::Refused, "declined on the device");
        if self.waiting_keys.iter().any(|(j, _)| j == job) {
            self.waiting_keys.retain(|(j, _)| j != job);
            return self.keys.finish(job, Err(declined()));
        }
        self.waiting.retain(|(j, _)| j != job);
        self.jobs.finish(job, Err(declined()))
    }

    fn check_secret(&self, secret: &Option<Secret>) -> Result<()> {
        if self.opts.collects == Collects::Nothing {
            return Ok(());
        }
        match secret {
            None => Err(SignerError::new(ErrorCode::Locked, "this signer needs its secret")),
            Some(s) if s.expose() != self.opts.secret => Err(SignerError::new(ErrorCode::WrongSecret, "wrong secret")),
            Some(_) => Ok(()),
        }
    }

    /// The seed's key at its unlock path, as a device works it out.
    fn key_now(&self, request: &UnlockKeyRequest) -> Result<UnlockKey> {
        let internal = |e: String| SignerError::new(ErrorCode::Internal, e);
        let path = DerivationPath::from_str(&unlock_key_path(request.index)?).map_err(|e| internal(e.to_string()))?;
        let at = XPrv::derive_from_path(self.seed, &path).map_err(|e| internal(e.to_string()))?;
        let point = at.public_key().public_key().to_encoded_point(true);
        Ok(UnlockKey {
            key: Secret::new(hex::encode(point.as_bytes())),
        })
    }

    fn held(&self, id: &str) -> Result<&Held> {
        self.accounts
            .iter()
            .find(|h| h.account.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| SignerError::new(ErrorCode::UnknownAccount, format!("no account {id}")))
    }

    fn sign_now(&self, request: &SignRequest) -> Result<Vec<Signature>> {
        let held = self.held(&request.account)?;
        let items = items_of(held, &request.payload)?;
        let mut sigs = items
            .iter()
            .enumerate()
            .map(|(i, item)| match self.opts.doctor {
                Doctor::OtherKey => sign_item(&held.other(), i, item),
                Doctor::OtherDigest => sign_item(held, i, &other_digest(item)),
                _ => sign_item(held, i, item),
            })
            .collect::<Result<Vec<_>>>()?;
        if self.opts.doctor == Doctor::DropLast {
            sigs.pop();
        }
        Ok(sigs)
    }
}

impl Held {
    /// The same account, keyed by one of its own children: a key it does not hold.
    fn other(&self) -> Held {
        let key = self
            .key
            .derive_child(ChildNumber::new(7, false).expect("child 7"))
            .expect("child key");
        Held {
            account: self.account.clone(),
            key,
        }
    }
}

/// What a request signs, one item per signature: a hash request's own items, or the digests of a
/// whole request, worked out here from what was handed over.
fn items_of(held: &Held, payload: &Payload) -> Result<Vec<HashItem>> {
    let evm = |data: &[u8]| {
        vec![HashItem {
            path: None,
            scheme: Scheme::Evm,
            digest: hex::encode(Keccak256::digest(data)),
        }]
    };
    match payload {
        Payload::Hash { items } => Ok(items.clone()),
        Payload::EvmTransaction { tx, .. } => Ok(evm(&unhex(tx)?)),
        Payload::EvmMessage { message } => {
            let bytes = unhex(message)?;
            let mut data = format!("\x19Ethereum Signed Message:\n{}", bytes.len()).into_bytes();
            data.extend_from_slice(&bytes);
            Ok(evm(&data))
        }
        Payload::EvmTypedData { .. } => Err(SignerError::new(
            ErrorCode::Unsupported,
            "the mock signs typed data as a hash only",
        )),
        Payload::BtcPsbt { psbt, .. } => psbt_items(held, psbt),
    }
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| SignerError::new(ErrorCode::Invalid, "not hex"))
}

/// One item per input: the path the PSBT gives for this signer's key, and the input's sighash.
fn psbt_items(held: &Held, psbt: &str) -> Result<Vec<HashItem>> {
    use bitcoin::bip32::{ChildNumber, KeySource};
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};

    let invalid = |m: String| SignerError::new(ErrorCode::Invalid, m);
    let psbt = bitcoin::Psbt::from_str(psbt.trim()).map_err(|e| invalid(format!("psbt: {e}")))?;
    let mine = held.account.fingerprint.as_deref().unwrap_or_default();
    let path_of = |(fp, path): &KeySource| {
        (fp.to_string() == mine).then(|| {
            let steps: Vec<String> = path
                .into_iter()
                .map(|c| match c {
                    ChildNumber::Normal { index } => index.to_string(),
                    ChildNumber::Hardened { index } => format!("{index}'"),
                })
                .collect();
            format!("m/{}", steps.join("/"))
        })
    };
    let prevouts = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| invalid(format!("input {i}: no witness utxo")))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let mut items = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        let not_mine = || invalid(format!("input {i}: no key of this signer"));
        let (scheme, path, digest) = match held.account.family {
            Family::Bitcoin => {
                let path = input.bip32_derivation.values().find_map(path_of).ok_or_else(not_mine)?;
                let prev = &prevouts[i];
                let h = cache
                    .p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
                    .map_err(|e| invalid(format!("input {i}: {e}")))?;
                (Scheme::Ecdsa, path, h.to_byte_array())
            }
            Family::BitcoinTaproot => {
                let path = input
                    .tap_key_origins
                    .values()
                    .find_map(|(_, source)| path_of(source))
                    .ok_or_else(not_mine)?;
                let ty = match input.sighash_type {
                    Some(t) => t.taproot_hash_ty().map_err(|e| invalid(format!("input {i}: {e}")))?,
                    None => TapSighashType::Default,
                };
                let h = cache
                    .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), ty)
                    .map_err(|e| invalid(format!("input {i}: {e}")))?;
                (Scheme::Bip86, path, h.to_byte_array())
            }
            Family::Evm => return Err(SignerError::new(ErrorCode::Unsupported, "a PSBT for an EVM account")),
        };
        items.push(HashItem {
            path: Some(path),
            scheme,
            digest: hex::encode(digest),
        });
    }
    Ok(items)
}

/// The same item over a digest with its last bit flipped.
fn other_digest(item: &HashItem) -> HashItem {
    let mut bytes = hex::decode(&item.digest).unwrap_or_default();
    if let Some(last) = bytes.last_mut() {
        *last ^= 1;
    }
    HashItem {
        digest: hex::encode(bytes),
        ..item.clone()
    }
}

fn sign_item(held: &Held, index: usize, item: &HashItem) -> Result<Signature> {
    let digest = hex32(&item.digest)?;
    let unsupported = || {
        SignerError::new(
            ErrorCode::Unsupported,
            format!("{:?} for {:?}", item.scheme, held.account.family),
        )
    };
    let mut key = held.key.clone();
    if held.account.family.is_bitcoin() {
        let base = held.account.path.as_deref().unwrap_or_default();
        let path = item
            .path
            .as_deref()
            .ok_or_else(|| SignerError::new(ErrorCode::Invalid, "Bitcoin item without a path"))?;
        for child in relative(base, path)? {
            key = key
                .derive_child(child)
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
        }
    } else if item.path.is_some() {
        return Err(SignerError::new(
            ErrorCode::Invalid,
            "an EVM account signs with its own key",
        ));
    }
    let secret = key.private_key().clone();
    match (held.account.family, item.scheme) {
        (Family::Evm, Scheme::Evm) | (Family::Bitcoin, Scheme::Ecdsa) => {
            let (sig, id) = secret
                .sign_prehash_recoverable(&digest)
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            let pubkey = PublicKey::from(secret.verifying_key());
            Ok(Signature {
                item: index,
                signature: hex::encode(sig.to_bytes()),
                recovery_id: (item.scheme == Scheme::Evm).then(|| id.to_byte()),
                pubkey: hex::encode(pubkey.to_encoded_point(true).as_bytes()),
            })
        }
        (Family::BitcoinTaproot, Scheme::Bip86) => {
            let internal = PublicKey::from(secret.verifying_key());
            let (tweak, output) = bip86_tweak(&internal)?;
            let mut d = *secret.as_nonzero_scalar().as_ref();
            if bool::from(internal.as_affine().y_is_odd()) {
                d = -d;
            }
            let signer = schnorr::SigningKey::from_bytes(&(d + tweak).to_bytes())
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            let sig = signer
                .sign_raw(&digest, &[0u8; 32])
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            Ok(Signature {
                item: index,
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
                pubkey: hex::encode(output.to_bytes()),
            })
        }
        _ => Err(unsupported()),
    }
}

impl Signer for MockSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: INTERFACE.into(),
            kind: self.opts.kind.clone(),
            model: "software keys".into(),
            families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
            request_kinds: self.opts.request_kinds.clone(),
            shows_request: self.opts.needs_confirmation,
            collects: self.opts.collects,
            unlock_key: true,
        }
    }

    fn accounts(&mut self) -> Result<Vec<Account>> {
        Ok(self.accounts.iter().map(|h| h.account.clone()).collect())
    }

    fn sign(&mut self, request: SignRequest) -> Result<String> {
        let held = self.held(&request.account)?;
        if let (Some(xpub), Some(key)) = (request.xpub.as_deref(), held.account.key.as_deref()) {
            check_xpub(key, held.account.family, held.account.chain, xpub)?;
        }
        if let Payload::Hash { items } = &request.payload {
            if items.iter().any(|i| i.path.as_deref().is_some_and(is_reserved)) {
                return Err(SignerError::new(
                    ErrorCode::Invalid,
                    "nothing signs under the reserved purpose",
                ));
            }
        }
        if !self.opts.request_kinds.contains(&request.payload.kind()) {
            return Err(SignerError::new(
                ErrorCode::Unsupported,
                format!("{:?}", request.payload.kind()),
            ));
        }
        self.check_secret(&request.secret)?;
        if self.opts.needs_confirmation {
            let job = self.jobs.start(JobState::ConfirmOnDevice);
            self.waiting.push((job.clone(), request));
            return Ok(job);
        }
        let job = self.jobs.start(JobState::Working);
        let outcome = self.sign_now(&request);
        self.jobs.finish(&job, outcome)?;
        Ok(job)
    }

    fn status(&mut self, job: &str) -> Result<JobStatus> {
        self.jobs.status(job)
    }

    fn result(&mut self, job: &str) -> Result<Vec<Signature>> {
        self.jobs.result(job)
    }

    fn cancel(&mut self, job: &str) -> Result<()> {
        self.waiting.retain(|(j, _)| j != job);
        self.jobs.cancel(job)
    }

    fn unlock_key(&mut self, request: UnlockKeyRequest) -> Result<String> {
        unlock_key_path(request.index)?;
        if !request.seed.eq_ignore_ascii_case(&self.recogniser) {
            return Err(SignerError::new(ErrorCode::WrongSeed, "not this signer's seed"));
        }
        if !self.accounts.iter().all(|h| h.account.available) {
            return Err(SignerError::new(ErrorCode::Unavailable, "the device is not connected"));
        }
        self.check_secret(&request.secret)?;
        if self.opts.needs_confirmation {
            let job = self.keys.start(JobState::ConfirmOnDevice);
            self.waiting_keys.push((job.clone(), request));
            return Ok(job);
        }
        let job = self.keys.start(JobState::Working);
        let outcome = self.key_now(&request);
        self.keys.finish(&job, outcome)?;
        Ok(job)
    }

    fn unlock_key_status(&mut self, job: &str) -> Result<JobStatus> {
        self.keys.status(job)
    }

    fn unlock_key_result(&mut self, job: &str) -> Result<UnlockKey> {
        self.keys.take(job)
    }

    fn cancel_unlock_key(&mut self, job: &str) -> Result<()> {
        self.waiting_keys.retain(|(j, _)| j != job);
        self.keys.cancel(job)
    }
}
