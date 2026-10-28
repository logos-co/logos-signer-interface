//! `logos.signer/1`: the contract every Logos signer module implements, so the signer manager can
//! list its accounts and have it sign. The IPC contract is `signer.lidl`; payloads are the JSON in
//! [`wire`], specified in `docs/interface.md`.

pub mod jobs;
pub mod sealed;
pub mod unlock;
pub mod verify;
pub mod wallets;
pub mod wire;

#[cfg(feature = "conformance")]
pub mod conformance;
#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "psbt")]
pub mod psbt;

pub use wire::{
    Account, Chain, Collects, ErrorCode, Family, HashItem, JobState, JobStatus, Payload, RequestKind, Result, Scheme,
    Secret, SignRequest, Signature, SignerError, SignerInfo, UnlockKey, UnlockKeyRequest,
};

pub const INTERFACE: &str = "logos.signer/1";

fn unsupported(what: &str) -> SignerError {
    SignerError::new(ErrorCode::Unsupported, format!("this signer has no {what}"))
}

/// A signer, in process. A module's glue maps each method onto the IPC contract with [`json`].
pub trait Signer {
    fn info(&self) -> SignerInfo;
    fn accounts(&mut self) -> Result<Vec<Account>>;
    /// Starts signing and returns a job id at once.
    fn sign(&mut self, request: SignRequest) -> Result<String>;
    fn status(&mut self, job: &str) -> Result<JobStatus>;
    fn result(&mut self, job: &str) -> Result<Vec<Signature>>;
    fn cancel(&mut self, job: &str) -> Result<()>;

    /// Starts working out a seed's unlock key ([`unlock`]) and returns a job id. Only the signer
    /// manager may call these four, and no public event carries their jobs.
    fn unlock_key(&mut self, _request: UnlockKeyRequest) -> Result<String> {
        Err(unsupported("unlock_key"))
    }
    fn unlock_key_status(&mut self, _job: &str) -> Result<JobStatus> {
        Err(unsupported("unlock_key"))
    }
    /// The answer, once: the job forgets it.
    fn unlock_key_result(&mut self, _job: &str) -> Result<UnlockKey> {
        Err(unsupported("unlock_key"))
    }
    fn cancel_unlock_key(&mut self, _job: &str) -> Result<()> {
        Err(unsupported("unlock_key"))
    }
}

/// The IPC replies, built from a [`Signer`], and read back by the manager.
pub mod json {
    use serde_json::json;

    use super::*;
    use crate::wire::{err, ok, parse_reply};

    fn reply<T>(r: Result<T>, f: impl FnOnce(T) -> serde_json::Value) -> String {
        match r {
            Ok(v) => ok(f(v)),
            Err(e) => err(&e),
        }
    }

    pub fn signer_info(s: &impl Signer) -> String {
        ok(serde_json::to_value(s.info()).unwrap_or_default())
    }

    pub fn signer_accounts(s: &mut impl Signer) -> String {
        reply(s.accounts(), |a| json!({ "accounts": a }))
    }

    pub fn sign(s: &mut impl Signer, request_json: &str) -> String {
        let request = serde_json::from_str::<SignRequest>(request_json)
            .map_err(|e| SignerError::new(ErrorCode::Invalid, format!("request: {e}")));
        reply(request.and_then(|r| s.sign(r)), |job| json!({ "job": job }))
    }

    pub fn sign_status(s: &mut impl Signer, job: &str) -> String {
        reply(s.status(job), |st| serde_json::to_value(st).unwrap_or_default())
    }

    pub fn sign_result(s: &mut impl Signer, job: &str) -> String {
        reply(s.result(job), |sigs| json!({ "job": job, "signatures": sigs }))
    }

    pub fn cancel_sign(s: &mut impl Signer, job: &str) -> String {
        reply(s.cancel(job), |_| json!({ "job": job }))
    }

    pub fn unlock_key(s: &mut impl Signer, request_json: &str) -> String {
        let request = serde_json::from_str::<UnlockKeyRequest>(request_json)
            .map_err(|e| SignerError::new(ErrorCode::Invalid, format!("request: {e}")));
        reply(request.and_then(|r| s.unlock_key(r)), |job| json!({ "job": job }))
    }

    pub fn unlock_key_status(s: &mut impl Signer, job: &str) -> String {
        reply(s.unlock_key_status(job), |st| {
            serde_json::to_value(st).unwrap_or_default()
        })
    }

    pub fn unlock_key_result(s: &mut impl Signer, job: &str) -> String {
        reply(s.unlock_key_result(job), |k| {
            let mut v = serde_json::to_value(k).unwrap_or_default();
            v["job"] = job.into();
            v
        })
    }

    pub fn cancel_unlock_key(s: &mut impl Signer, job: &str) -> String {
        reply(s.cancel_unlock_key(job), |_| json!({ "job": job }))
    }

    fn field<T: serde::de::DeserializeOwned>(v: serde_json::Value, name: Option<&str>) -> Result<T> {
        let v = match name {
            Some(n) => v.get(n).cloned().unwrap_or_default(),
            None => v,
        };
        serde_json::from_value(v).map_err(|e| SignerError::new(ErrorCode::Invalid, format!("reply: {e}")))
    }

    pub fn read_info(reply: &str) -> Result<SignerInfo> {
        field(parse_reply(reply)?, None)
    }

    pub fn read_accounts(reply: &str) -> Result<Vec<Account>> {
        field(parse_reply(reply)?, Some("accounts"))
    }

    pub fn read_job(reply: &str) -> Result<String> {
        field(parse_reply(reply)?, Some("job"))
    }

    pub fn read_status(reply: &str) -> Result<JobStatus> {
        field(parse_reply(reply)?, None)
    }

    pub fn read_signatures(reply: &str) -> Result<Vec<Signature>> {
        field(parse_reply(reply)?, Some("signatures"))
    }

    pub fn read_unlock_key(reply: &str) -> Result<UnlockKey> {
        field(parse_reply(reply)?, None)
    }
}
