//! Job bookkeeping a signer module can reuse: random ids, states, results kept until forgotten.

use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::wire::{ErrorCode, JobState, JobStatus, Result, Signature, SignerError, UnlockKey};

/// A finished job's answer is kept this long after it settles.
pub const RETENTION: Duration = Duration::from_secs(600);
/// An unlock key nobody reads is wiped this soon after its job settles.
pub const KEY_RETENTION: Duration = Duration::from_secs(60);

struct Job {
    id: String,
    state: JobState,
    error: Option<SignerError>,
    signatures: Option<Vec<Signature>>,
    settled_at: Option<Instant>,
}

#[derive(Default)]
pub struct JobTable {
    jobs: Vec<Job>,
}

impl JobTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.jobs
            .retain(|j| j.settled_at.is_none_or(|at| now.duration_since(at) < RETENTION));
    }

    fn find(&mut self, id: &str) -> Result<&mut Job> {
        self.jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| SignerError::new(ErrorCode::UnknownJob, format!("no job {id}")))
    }

    pub fn start(&mut self, state: JobState) -> String {
        self.sweep();
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let id = format!("job_{}", hex::encode(raw));
        self.jobs.push(Job {
            id: id.clone(),
            state,
            error: None,
            signatures: None,
            settled_at: None,
        });
        id
    }

    /// Move a live job to another live state, such as waiting for the device.
    pub fn set_state(&mut self, id: &str, state: JobState) -> Result<()> {
        let job = self.find(id)?;
        if !job.state.is_final() {
            job.state = state;
        }
        Ok(())
    }

    /// Settle a live job with its signatures or its error. A cancelled job stays cancelled.
    pub fn finish(&mut self, id: &str, outcome: Result<Vec<Signature>>) -> Result<()> {
        let job = self.find(id)?;
        if job.state.is_final() {
            return Ok(());
        }
        match outcome {
            Ok(sigs) => {
                job.state = JobState::Done;
                job.signatures = Some(sigs);
            }
            Err(e) => {
                job.state = if e.code == ErrorCode::Refused {
                    JobState::Refused
                } else {
                    JobState::Failed
                };
                job.error = Some(e);
            }
        }
        job.settled_at = Some(Instant::now());
        Ok(())
    }

    pub fn status(&mut self, id: &str) -> Result<JobStatus> {
        self.sweep();
        let job = self.find(id)?;
        Ok(JobStatus {
            job: job.id.clone(),
            state: job.state,
            error: job.error.clone(),
        })
    }

    /// The signatures of a done job, as often as asked until it is swept.
    pub fn result(&mut self, id: &str) -> Result<Vec<Signature>> {
        self.sweep();
        let job = self.find(id)?;
        match (&job.state, &job.signatures) {
            (JobState::Done, Some(s)) => Ok(s.clone()),
            (state, _) if !state.is_final() => Err(SignerError::new(
                ErrorCode::Busy,
                format!("job {id} is still {}", state.as_str()),
            )),
            _ => Err(job
                .error
                .clone()
                .unwrap_or_else(|| SignerError::new(ErrorCode::Invalid, format!("job {id} has no signatures")))),
        }
    }

    pub fn cancel(&mut self, id: &str) -> Result<()> {
        self.sweep();
        let job = self.find(id)?;
        if !job.state.is_final() {
            job.state = JobState::Cancelled;
            job.settled_at = Some(Instant::now());
        }
        Ok(())
    }

    /// Live jobs, oldest first.
    pub fn live(&self) -> Vec<String> {
        self.jobs
            .iter()
            .filter(|j| !j.state.is_final())
            .map(|j| j.id.clone())
            .collect()
    }
}

struct KeyJob {
    id: String,
    state: JobState,
    error: Option<SignerError>,
    key: Option<UnlockKey>,
    settled_at: Option<Instant>,
}

/// `unlock_key` jobs: as [`JobTable`], but an answer is read once and then forgotten.
#[derive(Default)]
pub struct KeyJobs {
    jobs: Vec<KeyJob>,
}

impl KeyJobs {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.jobs
            .retain(|j| j.settled_at.is_none_or(|at| now.duration_since(at) < KEY_RETENTION));
    }

    fn find(&mut self, id: &str) -> Result<&mut KeyJob> {
        self.jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| SignerError::new(ErrorCode::UnknownJob, format!("no job {id}")))
    }

    pub fn start(&mut self, state: JobState) -> String {
        self.sweep();
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let id = format!("key_{}", hex::encode(raw));
        self.jobs.push(KeyJob {
            id: id.clone(),
            state,
            error: None,
            key: None,
            settled_at: None,
        });
        id
    }

    pub fn set_state(&mut self, id: &str, state: JobState) -> Result<()> {
        let job = self.find(id)?;
        if !job.state.is_final() {
            job.state = state;
        }
        Ok(())
    }

    pub fn finish(&mut self, id: &str, outcome: Result<UnlockKey>) -> Result<()> {
        let job = self.find(id)?;
        if job.state.is_final() {
            return Ok(());
        }
        match outcome {
            Ok(key) => {
                job.state = JobState::Done;
                job.key = Some(key);
            }
            Err(e) => {
                job.state = if e.code == ErrorCode::Refused {
                    JobState::Refused
                } else {
                    JobState::Failed
                };
                job.error = Some(e);
            }
        }
        job.settled_at = Some(Instant::now());
        Ok(())
    }

    pub fn status(&mut self, id: &str) -> Result<JobStatus> {
        self.sweep();
        let job = self.find(id)?;
        Ok(JobStatus {
            job: job.id.clone(),
            state: job.state,
            error: job.error.clone(),
        })
    }

    /// The answer of a done job, once.
    pub fn take(&mut self, id: &str) -> Result<UnlockKey> {
        self.sweep();
        let job = self.find(id)?;
        match (job.state, job.key.take()) {
            (JobState::Done, Some(k)) => Ok(k),
            (JobState::Done, None) => Err(SignerError::new(
                ErrorCode::Invalid,
                format!("job {id} was read already"),
            )),
            (state, _) if !state.is_final() => Err(SignerError::new(
                ErrorCode::Busy,
                format!("job {id} is still {}", state.as_str()),
            )),
            _ => Err(job
                .error
                .clone()
                .unwrap_or_else(|| SignerError::new(ErrorCode::Invalid, format!("job {id} has no key")))),
        }
    }

    pub fn cancel(&mut self, id: &str) -> Result<()> {
        self.sweep();
        let job = self.find(id)?;
        if !job.state.is_final() {
            job.state = JobState::Cancelled;
            job.settled_at = Some(Instant::now());
        }
        Ok(())
    }

    pub fn live(&self) -> Vec<String> {
        self.jobs
            .iter()
            .filter(|j| !j.state.is_final())
            .map(|j| j.id.clone())
            .collect()
    }
}
