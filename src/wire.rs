//! The JSON every `logos.signer/1` method takes and returns. Field names are camelCase.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Evm,
    /// Native segwit, BIP84.
    Bitcoin,
    /// Taproot key path, BIP86.
    BitcoinTaproot,
}

impl Family {
    pub fn is_bitcoin(self) -> bool {
        matches!(self, Family::Bitcoin | Family::BitcoinTaproot)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    Main,
    Test,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Hash,
    EvmTransaction,
    EvmMessage,
    EvmTypedData,
    BtcPsbt,
}

/// What the host collects from the person before `sign`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Collects {
    Nothing,
    Password,
    Pin,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignerInfo {
    pub interface: String,
    /// `keystore`, `keycard`, `keycard_shell`, `ledger`, `trezor`, `qr`, `mock`.
    pub kind: String,
    #[serde(default)]
    pub model: String,
    pub families: Vec<Family>,
    pub request_kinds: Vec<RequestKind>,
    /// The device shows the request on its own screen.
    pub shows_request: bool,
    pub collects: Collects,
    /// Answers `unlock_key`: the key, from a seed, that unlocks that seed's data.
    #[serde(default)]
    pub unlock_key: bool,
}

/// Public material only. `id` is what `sign` names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub family: Family,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Chain>,
    /// The account's own path; Bitcoin items sign below it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Master fingerprint, 8 hex digits: the wallet the account derives from. A Bitcoin account
    /// always carries it; an EVM account should whenever the signer knows its seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// A Bitcoin account's xpub. Listed to the signer manager only, and only while the account's
    /// seed is unlocked: at rest a signer keeps it encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
    /// A Bitcoin account's roster key ([`crate::unlock::roster_key`]): what other signers' copies of it
    /// share, whatever the xpub's metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The seed the account comes from, as this signer names it: a Keycard's key UID, a Shell's
    /// master key id, a QR wallet's master fingerprint, a keystore wallet's id. `unlock_key` takes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub available: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// Recoverable ECDSA over an EVM digest; the answer carries the recovery id.
    Evm,
    /// ECDSA with low S, for native segwit.
    Ecdsa,
    /// BIP340 with the BIP86 key-path tweak.
    Bip86,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HashItem {
    /// Full path for a Bitcoin account; absent for an EVM account, which signs with its own key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub scheme: Scheme,
    /// 32 bytes, hex.
    pub digest: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum Payload {
    Hash {
        items: Vec<HashItem>,
    },
    EvmTransaction {
        chain_id: u64,
        /// Unsigned EIP-2718 bytes, hex.
        tx: String,
    },
    EvmMessage {
        /// The bytes `personal_sign` covers, hex.
        message: String,
    },
    EvmTypedData {
        typed_data: serde_json::Value,
    },
    BtcPsbt {
        network: String,
        /// Base64.
        psbt: String,
    },
}

impl Payload {
    pub fn kind(&self) -> RequestKind {
        match self {
            Payload::Hash { .. } => RequestKind::Hash,
            Payload::EvmTransaction { .. } => RequestKind::EvmTransaction,
            Payload::EvmMessage { .. } => RequestKind::EvmMessage,
            Payload::EvmTypedData { .. } => RequestKind::EvmTypedData,
            Payload::BtcPsbt { .. } => RequestKind::BtcPsbt,
        }
    }
}

/// A password or PIN. Wiped on drop, never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(Zeroizing::new(s.into()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(Secret(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub account: String,
    #[serde(flatten)]
    pub payload: Payload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    /// A Bitcoin account's xpub, from the wallet that has it open. The signer checks it against the
    /// account's roster key before using it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
}

/// What the manager asks for when a seed unlocks. A module may read more fields from the same JSON,
/// such as an account another module routes to it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnlockKeyRequest {
    /// The seed, as this signer names it ([`Account::seed`]).
    pub seed: String,
    /// The seed's unlock index ([`crate::unlock::unlock_key_path`]).
    #[serde(default)]
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
}

/// A seed's unlock key: the compressed public key at its unlock path, 33 bytes as hex.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnlockKey {
    pub key: Secret,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Working,
    /// The person has to confirm on the device.
    ConfirmOnDevice,
    Done,
    Refused,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_final(self) -> bool {
        matches!(
            self,
            JobState::Done | JobState::Refused | JobState::Failed | JobState::Cancelled
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Working => "working",
            JobState::ConfirmOnDevice => "confirm_on_device",
            JobState::Done => "done",
            JobState::Refused => "refused",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JobStatus {
    pub job: String,
    pub state: JobState,
    /// Flattened: a failed job carries `code` and `error` beside its state.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SignerError>,
}

/// One signature, for the request item or PSBT input it belongs to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub item: usize,
    /// 64 bytes r‖s, or a BIP340 signature, hex.
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
    /// The key that signed: 33 bytes compressed, or 32 bytes x-only for BIP340, hex.
    pub pubkey: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Needs a secret or an unlock, and has neither.
    Locked,
    WrongSecret,
    UnknownAccount,
    UnknownJob,
    /// A kind, family or scheme this signer doesn't sign.
    Unsupported,
    /// The device is unplugged, locked or has the wrong app open.
    Unavailable,
    Busy,
    /// The person declined on the device.
    Refused,
    Invalid,
    Internal,
    /// The device holds another seed than the account's.
    WrongSeed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignerError {
    pub code: ErrorCode,
    #[serde(rename = "error")]
    pub message: String,
}

impl SignerError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        SignerError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SignerError {}

pub type Result<T> = std::result::Result<T, SignerError>;

/// `{ ok: true, ...fields }`.
pub fn ok(fields: serde_json::Value) -> String {
    let mut v = match fields {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    v.insert("ok".into(), true.into());
    serde_json::Value::Object(v).to_string()
}

/// `{ ok: false, code, error }`.
pub fn err(e: &SignerError) -> String {
    serde_json::json!({ "ok": false, "code": e.code, "error": e.message }).to_string()
}

/// Read a reply: its fields on `ok`, its error otherwise.
pub fn parse_reply(reply: &str) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(reply)
        .map_err(|e| SignerError::new(ErrorCode::Invalid, format!("reply is not JSON: {e}")))?;
    if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
        return Ok(v);
    }
    let code = v
        .get("code")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or(ErrorCode::Internal);
    let message = v.get("error").and_then(|m| m.as_str()).unwrap_or("no error given");
    Err(SignerError::new(code, message))
}
