//! The agent's clock: every reading of the time goes through here, never through std's `Instant`
//! or `SystemTime`, `mpsc::Receiver::recv_timeout` or rustls's default time provider.
//!
//! Why: on 32-bit ARM, musl (1.2, 64-bit `time_t`) reads the clock with the `clock_gettime64`
//! syscall (403, Linux 5.1+) and falls back to the old `clock_gettime` (263) only on `ENOSYS`.
//! Synology's Linux 3.10 kernels for ARM (the DS2015xs, `alpine`) have their own syscall at 403
//! ("archive bit"; `dmesg` logs `Archive bit cmd:<the timespec pointer> not implement.`), which
//! answers `EINVAL`. musl passes that on, std unwraps it and panics (`time.rs`, os error 22), and
//! the connection's thread dies: the client sees a reset during or after the TLS handshake. Here
//! 32-bit ARM makes the old syscall itself; every other target uses `clock_gettime`, which has
//! only the one syscall there. A failed reading never panics: `Instant` falls back to the wall
//! clock, and a reading that goes backwards counts as zero.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::OnceLock;
use std::time::Duration;

static MONOTONIC_AVAILABLE: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub struct Instant {
    ticks: Duration,
    monotonic: bool,
}

impl Instant {
    pub fn now() -> Self {
        let monotonic = *MONOTONIC_AVAILABLE.get_or_init(|| gettime(libc::CLOCK_MONOTONIC).is_some());
        if monotonic {
            if let Some(ticks) = gettime(libc::CLOCK_MONOTONIC) {
                return Self { ticks, monotonic: true };
            }
        }
        Self { ticks: unix_now(), monotonic: false }
    }

    pub fn duration_since(&self, earlier: Self) -> Duration {
        if self.monotonic == earlier.monotonic {
            self.ticks.saturating_sub(earlier.ticks)
        } else {
            Duration::ZERO
        }
    }

    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }
}

/// The wall clock, since the Unix epoch (zero when it cannot be read).
pub fn unix_now() -> Duration {
    wall().unwrap_or_default()
}

/// The wall clock, since the Unix epoch, or None when it cannot be read.
pub fn wall() -> Option<Duration> {
    gettime(libc::CLOCK_REALTIME)
}

/// `rx.recv_timeout(timeout)` without std's `Instant`: Err on timeout or a closed channel.
pub fn recv_timeout<T>(rx: &Receiver<T>, timeout: Duration) -> Result<T, ()> {
    let start = Instant::now();
    loop {
        match rx.try_recv() {
            Ok(v) => return Ok(v),
            Err(TryRecvError::Disconnected) => return Err(()),
            Err(TryRecvError::Empty) if start.elapsed() >= timeout => return Err(()),
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(2)),
        }
    }
}

/// 32-bit ARM: the old `clock_gettime` syscall with a 32-bit `timespec`, not musl's (see the top).
#[cfg(target_arch = "arm")]
fn gettime(clock: libc::clockid_t) -> Option<Duration> {
    let mut ts: [libc::c_long; 2] = [0, 0];
    if unsafe { libc::syscall(libc::SYS_clock_gettime, clock as libc::c_long, ts.as_mut_ptr()) } != 0 {
        return None;
    }
    Some(Duration::new(ts[0].max(0) as u64, ts[1].clamp(0, 999_999_999) as u32))
}

#[cfg(not(target_arch = "arm"))]
fn gettime(clock: libc::clockid_t) -> Option<Duration> {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(clock, ts.as_mut_ptr()) } != 0 {
        return None;
    }
    let ts = unsafe { ts.assume_init() };
    Some(Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_time_never_underflows() {
        let later = Instant { ticks: Duration::from_secs(2), monotonic: false };
        let earlier = Instant { ticks: Duration::from_secs(3), monotonic: false };
        assert_eq!(later.duration_since(earlier), Duration::ZERO);
    }

    #[test]
    fn now_returns_a_usable_timestamp() {
        let start = Instant::now();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn both_clocks_read_and_agree_with_std() {
        assert!(gettime(libc::CLOCK_MONOTONIC).is_some());
        let ours = unix_now().as_secs();
        let std = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(ours.abs_diff(std) <= 2, "{ours} vs {std}");
    }

    /// The failure only shows on the NAS (qemu-user and every CI kernel answer 403 as expected), so
    /// the rule is checked in the sources: nothing but this file reads std's clocks.
    #[test]
    fn nothing_else_reads_std_clocks() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name == "clock.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                let std_instant = line.contains("std::time") && line.contains("Instant");
                let other = ["SystemTime::now", ".recv_timeout(", ".wait_timeout", "park_timeout", "builder_with_provider("]
                    .iter()
                    .any(|bad| line.contains(bad));
                assert!(!std_instant && !other, "{name}:{}: use crate::clock instead: {}", n + 1, line.trim());
            }
        }
    }

    #[test]
    fn recv_timeout_returns_a_value_times_out_and_sees_a_closed_channel() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(7).unwrap();
        assert_eq!(recv_timeout(&rx, Duration::from_secs(1)), Ok(7));
        let start = Instant::now();
        assert_eq!(recv_timeout(&rx, Duration::from_millis(50)), Err(()));
        assert!(start.elapsed() >= Duration::from_millis(50));
        drop(tx);
        assert_eq!(recv_timeout(&rx, Duration::from_secs(5)), Err(()));
    }
}
