use std::sync::atomic::{AtomicU64, Ordering};

/// A Lamport clock for causal ordering.
#[derive(Debug)]
pub struct LamportClock {
    counter: AtomicU64,
}

impl LamportClock {
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Increment and return the new value (local event).
    pub fn tick(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Merge with a received timestamp and return the new value.
    pub fn witness(&self, received: u64) -> u64 {
        loop {
            let current = self.counter.load(Ordering::SeqCst);
            let new_val = current.max(received) + 1;
            if self
                .counter
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return new_val;
            }
        }
    }

    /// Current value without incrementing.
    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

/// Returns wall-clock time in nanoseconds since Unix epoch.
pub fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_increments() {
        let clock = LamportClock::new();
        assert_eq!(clock.tick(), 1);
        assert_eq!(clock.tick(), 2);
        assert_eq!(clock.tick(), 3);
    }

    #[test]
    fn witness_advances_past_received() {
        let clock = LamportClock::new();
        clock.tick(); // 1
        let val = clock.witness(10);
        assert_eq!(val, 11);
        assert_eq!(clock.current(), 11);
    }
}
