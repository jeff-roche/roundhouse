use roundhouse_core::Tier;
use std::process::ExitStatus;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::Duration;
use tokio::process::{Child as TokioChild, ChildStderr, ChildStdout};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Handle {
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub achieved: Tier,
    pub degradations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Clone)]
pub struct Child {
    pub pid: u32,
    process: Arc<Mutex<Option<TokioChild>>>,
    running: Arc<AtomicBool>,
    exit_status: Arc<StdMutex<Option<ExitStatus>>>,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Child")
            .field("pid", &self.pid)
            .field("running", &self.is_running())
            .finish()
    }
}

impl Child {
    pub(crate) fn from_process_internal(pid: u32, process: TokioChild) -> Self {
        let process = Arc::new(Mutex::new(Some(process)));
        let running = Arc::new(AtomicBool::new(true));
        let exit_status = Arc::new(StdMutex::new(None));
        let monitor_process = process.clone();
        let monitor_running = running.clone();
        let monitor_status = exit_status.clone();
        tokio::spawn(async move {
            loop {
                let result = {
                    let mut process = monitor_process.lock().await;
                    process.as_mut().map(TokioChild::try_wait)
                };
                match result {
                    Some(Ok(Some(status))) => {
                        if let Ok(mut saved) = monitor_status.lock() {
                            *saved = Some(status);
                        }
                        monitor_running.store(false, Ordering::Release);
                        break;
                    }
                    Some(Ok(None)) => {}
                    Some(Err(_)) | None => {
                        monitor_running.store(false, Ordering::Release);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        Self {
            pid,
            process,
            running,
            exit_status,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub fn from_process(pid: u32, process: TokioChild) -> Self {
        Self::from_process_internal(pid, process)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_running(&self) -> bool {
        if !self.running.load(Ordering::Acquire) {
            return false;
        }
        #[cfg(unix)]
        {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.pid as i32), None).is_err() {
                return false;
            }
            #[cfg(target_os = "linux")]
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)) {
                if stat
                    .rsplit_once(')')
                    .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
                {
                    return false;
                }
            }
        }
        self.running.load(Ordering::Acquire)
    }

    pub async fn take_stdio(&self) -> (Option<ChildStdout>, Option<ChildStderr>) {
        let mut process = self.process.lock().await;
        let Some(process) = process.as_mut() else {
            return (None, None);
        };
        (process.stdout.take(), process.stderr.take())
    }

    pub async fn wait(&self) -> std::io::Result<ExitStatus> {
        if let Ok(saved) = self.exit_status.lock() {
            if let Some(status) = *saved {
                return Ok(status);
            }
        }
        let mut process = self.process.lock().await;
        let child = process
            .as_mut()
            .ok_or_else(|| std::io::Error::other("isolated child is unavailable"))?;
        let status = child.wait().await;
        let status = status?;
        if let Ok(mut saved) = self.exit_status.lock() {
            *saved = Some(status);
        }
        self.running.store(false, Ordering::Release);
        Ok(status)
    }

    pub async fn cancel(&self) -> std::io::Result<ExitStatus> {
        #[cfg(unix)]
        let mut direct_status = None;
        #[cfg(unix)]
        {
            signal_group(self.pid, libc::SIGTERM)?;
            let term_result = tokio::time::timeout(Duration::from_secs(5), self.wait()).await;
            if let Ok(status) = term_result {
                let status = status?;
                if group_is_empty(self.pid) {
                    return Ok(status);
                }
                direct_status = Some(status);
            }
            signal_group(self.pid, libc::SIGKILL)?;
        }

        #[cfg(unix)]
        let status = if let Some(status) = direct_status {
            status
        } else {
            let mut process = self.process.lock().await;
            let child = process
                .as_mut()
                .ok_or_else(|| std::io::Error::other("isolated child is unavailable"))?;
            let _ = child.start_kill();
            child.wait().await?
        };
        #[cfg(not(unix))]
        let status = {
            let mut process = self.process.lock().await;
            let child = process
                .as_mut()
                .ok_or_else(|| std::io::Error::other("isolated child is unavailable"))?;
            let _ = child.start_kill();
            child.wait().await?
        };
        self.running.store(false, Ordering::Release);

        #[cfg(unix)]
        if !wait_for_empty_group(self.pid).await {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "isolated process group did not terminate",
            ));
        }

        Ok(status)
    }
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: i32) -> std::io::Result<()> {
    // bwrap is started as its own process-group leader; its command inherits
    // that group even though it runs inside bwrap's PID namespace.
    let signal = nix::sys::signal::Signal::try_from(signal).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported process signal",
        )
    })?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(-(pid as i32)), signal)
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        .or_else(|error| {
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        })
}

#[cfg(unix)]
fn group_is_empty(pid: u32) -> bool {
    matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(-(pid as i32)), None,),
        Err(nix::errno::Errno::ESRCH)
    )
}

#[cfg(unix)]
async fn wait_for_empty_group(pid: u32) -> bool {
    for _ in 0..25 {
        if group_is_empty(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    group_is_empty(pid)
}

#[derive(Debug, Clone)]
pub struct Attestation {
    pub tier: Tier,
    pub digest: String,
    pub net_enforced: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error("isolation mechanism unsupported on this host: {0}")]
    Unsupported(String),
    #[error("achieved tier is lower than requested and on_degrade=Refuse")]
    DegradedBelowRequested,
}
