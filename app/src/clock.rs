//! A monotonic clock in milliseconds, as Android's SystemClock.elapsedRealtime gave it.
//! [`elapsed_realtime`] counts suspend (as the health checks and timed pauses expect), [`uptime_millis`] doesn't.

/// Milliseconds since boot, suspend included (CLOCK_BOOTTIME).
pub fn elapsed_realtime() -> i64 {
    millis(libc::CLOCK_BOOTTIME).unwrap_or_else(uptime_millis)
}

/// Milliseconds since boot without suspend (CLOCK_MONOTONIC).
pub fn uptime_millis() -> i64 {
    millis(libc::CLOCK_MONOTONIC).unwrap_or(0)
}

fn millis(clock: libc::clockid_t) -> Option<i64> {
    // SAFETY: timespec is plain data; all-zero is a valid value for clock_gettime to overwrite.
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: t is a valid, writable timespec.
    (unsafe { libc::clock_gettime(clock, &mut t) } == 0).then(|| t.tv_sec as i64 * 1000 + t.tv_nsec as i64 / 1_000_000)
}
