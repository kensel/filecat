//! An `Instant` that never panics, for timeouts, deadlines and the `activity` ages. std's
//! `Instant::now` unwraps `clock_gettime(CLOCK_MONOTONIC)` and panics when it fails or returns an
//! out-of-range `tv_nsec`; a panic there ends the connection, which the client sees as a TLS
//! error (suspected on an armv7 Synology). This one clamps the reading and, when the monotonic
//! clock is not usable, falls back to
//! the wall clock; a reading that goes backwards counts as zero. Wall-clock dates
//! (`SystemTime`) are not covered.

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
        let monotonic = *MONOTONIC_AVAILABLE.get_or_init(|| read_monotonic().is_some());
        if monotonic {
            if let Some(ticks) = read_monotonic() {
                return Self {
                    ticks,
                    monotonic: true,
                };
            }
        }
        Self {
            ticks: read_wall_clock(),
            monotonic: false,
        }
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

fn read_monotonic() -> Option<Duration> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return None;
    }
    let time = unsafe { time.assume_init() };
    Some(Duration::new(
        time.tv_sec.max(0) as u64,
        time.tv_nsec.clamp(0, 999_999_999) as u32,
    ))
}

fn read_wall_clock() -> Duration {
    let mut time = std::mem::MaybeUninit::<libc::timeval>::uninit();
    if unsafe { libc::gettimeofday(time.as_mut_ptr(), std::ptr::null_mut()) } != 0 {
        return Duration::ZERO;
    }
    let time = unsafe { time.assume_init() };
    Duration::new(
        time.tv_sec.max(0) as u64,
        time.tv_usec.clamp(0, 999_999) as u32 * 1_000,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_time_never_underflows() {
        let later = Instant {
            ticks: Duration::from_secs(2),
            monotonic: false,
        };
        let earlier = Instant {
            ticks: Duration::from_secs(3),
            monotonic: false,
        };
        assert_eq!(later.duration_since(earlier), Duration::ZERO);
    }

    #[test]
    fn now_returns_a_usable_timestamp() {
        let start = Instant::now();
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
