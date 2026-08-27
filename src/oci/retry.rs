//! Retry classification and backoff.
//!
//! Kept free of any HTTP type so the decision table can be tested without a
//! network. `client.rs` translates a real response or transport failure into a
//! [`Outcome`] and asks this module what to do.
//!
//! The central safety rule: a request is only retried when replaying it is
//! provably harmless. Reads always qualify. Writes qualify only when the call
//! site has established replay safety, which for OCI means an idempotency or
//! retry token (see [`RequestKind`]).

use std::time::Duration;

/// How a single attempt ended, reduced to what the retry decision needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// OCI answered with this status. `retry_after` is the parsed `Retry-After`
    /// header when the service supplied one.
    Status {
        code: u16,
        retry_after: Option<Duration>,
    },
    /// DNS, TCP connect, or TLS handshake failure. No request was processed.
    Connect,
    /// The attempt exceeded its deadline.
    Timeout,
    /// The connection dropped while the response body was being read.
    BodyIncomplete,
}

/// Whether replaying this request is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// A read. Replaying changes nothing.
    Read,
    /// A write carrying an OCI retry/idempotency token, so a duplicate delivery
    /// is collapsed server-side.
    IdempotentWrite,
    /// A write with no replay protection. Never retried automatically.
    UnsafeWrite,
}

impl RequestKind {
    /// Whether a transport-level failure (no status received) may be replayed.
    ///
    /// A connect failure means the request never reached OCI, but this client
    /// cannot always distinguish "never sent" from "sent, reply lost", so an
    /// unsafe write is still not replayed.
    #[must_use]
    fn may_replay(self) -> bool {
        matches!(self, Self::Read | Self::IdempotentWrite)
    }
}

/// Bounded exponential backoff with full jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts including the first, so 1 disables retrying.
    pub max_attempts: u32,
    /// Delay before the second attempt; doubles from there.
    pub base_delay: Duration,
    /// Ceiling for any single delay, including a server `Retry-After`.
    pub max_delay: Duration,
    /// Ceiling for time spent sleeping across the whole call.
    pub max_total_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            max_total_delay: Duration::from_secs(20),
        }
    }
}

/// What the caller should do after an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Sleep for this long, then try again.
    RetryAfter(Duration),
    /// Give up and surface the failure.
    Stop,
}

impl RetryPolicy {
    /// Decide whether to retry.
    ///
    /// `attempt` is 1-based: 1 is the original request. `elapsed_delay` is the
    /// time already spent sleeping, which bounds total added latency.
    /// `jitter` must be in `[0, 1)` and is supplied by the caller so this stays
    /// deterministic under test.
    #[must_use]
    pub fn decide(
        &self,
        kind: RequestKind,
        outcome: Outcome,
        attempt: u32,
        elapsed_delay: Duration,
        jitter: f64,
    ) -> Decision {
        if attempt >= self.max_attempts || !is_retryable(kind, outcome) {
            return Decision::Stop;
        }

        let delay = self.delay_for(attempt, retry_after_of(outcome), jitter);
        if elapsed_delay.saturating_add(delay) > self.max_total_delay {
            return Decision::Stop;
        }
        Decision::RetryAfter(delay)
    }

    /// Delay before the attempt following `attempt`.
    ///
    /// A server-supplied `Retry-After` wins over the computed backoff because
    /// OCI knows better when it will accept traffic again, but it is still
    /// capped: a hostile or mistaken header must not stall the CLI.
    #[must_use]
    pub fn delay_for(&self, attempt: u32, retry_after: Option<Duration>, jitter: f64) -> Duration {
        if let Some(server) = retry_after {
            return server.min(self.max_delay);
        }

        let exponent = attempt.saturating_sub(1).min(16);
        let scaled = self
            .base_delay
            .saturating_mul(2u32.saturating_pow(exponent))
            .min(self.max_delay);

        // Full jitter: sample uniformly from [0, scaled]. This spreads retries
        // from concurrent processes instead of synchronising them.
        let jitter = jitter.clamp(0.0, 1.0);
        Duration::from_secs_f64(scaled.as_secs_f64() * jitter)
    }
}

/// Whether this outcome is worth retrying for this kind of request.
#[must_use]
pub fn is_retryable(kind: RequestKind, outcome: Outcome) -> bool {
    match outcome {
        Outcome::Status { code, .. } => match code {
            // Throttling: always safe to retry, the request was rejected.
            429 => true,
            // Transient server-side failures. 501 and 505 are deliberately
            // excluded: they mean "this will never work", not "try later".
            500 | 502 | 503 | 504 => kind != RequestKind::UnsafeWrite,
            _ => false,
        },
        Outcome::Connect | Outcome::Timeout | Outcome::BodyIncomplete => kind.may_replay(),
    }
}

fn retry_after_of(outcome: Outcome) -> Option<Duration> {
    match outcome {
        Outcome::Status { retry_after, .. } => retry_after,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Decision, Outcome, RequestKind, RetryPolicy, is_retryable};

    fn status(code: u16) -> Outcome {
        Outcome::Status {
            code,
            retry_after: None,
        }
    }

    #[test]
    fn throttling_and_transient_server_errors_retry_reads() {
        for code in [429, 500, 502, 503, 504] {
            assert!(
                is_retryable(RequestKind::Read, status(code)),
                "{code} should retry"
            );
        }
    }

    #[test]
    fn client_errors_and_permanent_server_errors_never_retry() {
        for code in [200, 400, 401, 403, 404, 409, 422, 501, 505] {
            assert!(
                !is_retryable(RequestKind::Read, status(code)),
                "{code} must not retry"
            );
        }
    }

    /// The core write-safety invariant: a write with no replay protection is
    /// never retried, no matter how transient the failure looks.
    #[test]
    fn unsafe_writes_are_never_retried() {
        let outcomes = [
            status(500),
            status(503),
            Outcome::Connect,
            Outcome::Timeout,
            Outcome::BodyIncomplete,
        ];
        for outcome in outcomes {
            assert!(
                !is_retryable(RequestKind::UnsafeWrite, outcome),
                "{outcome:?} must not retry an unsafe write"
            );
        }
    }

    /// 429 is the one exception: the request was refused, not processed, so
    /// even an unprotected write can safely be re-sent.
    #[test]
    fn throttled_unsafe_writes_may_retry() {
        assert!(is_retryable(RequestKind::UnsafeWrite, status(429)));
    }

    #[test]
    fn idempotent_writes_retry_like_reads() {
        for outcome in [status(503), Outcome::Connect, Outcome::Timeout] {
            assert!(is_retryable(RequestKind::IdempotentWrite, outcome));
        }
    }

    #[test]
    fn attempts_are_bounded() {
        let policy = RetryPolicy::default();
        let last = policy.max_attempts;
        assert_eq!(
            policy.decide(RequestKind::Read, status(503), last, Duration::ZERO, 1.0),
            Decision::Stop,
            "the final attempt must not schedule another"
        );
        assert!(matches!(
            policy.decide(
                RequestKind::Read,
                status(503),
                last - 1,
                Duration::ZERO,
                1.0
            ),
            Decision::RetryAfter(_)
        ));
    }

    #[test]
    fn total_delay_is_bounded() {
        let policy = RetryPolicy::default();
        let nearly_spent = policy.max_total_delay - Duration::from_millis(1);
        assert_eq!(
            policy.decide(RequestKind::Read, status(503), 1, nearly_spent, 1.0),
            Decision::Stop,
            "must stop rather than exceed the total delay budget"
        );
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let policy = RetryPolicy::default();
        // With jitter at its maximum the delay equals the full backoff window.
        let first = policy.delay_for(1, None, 1.0);
        let second = policy.delay_for(2, None, 1.0);
        let third = policy.delay_for(3, None, 1.0);
        assert_eq!(first, policy.base_delay);
        assert_eq!(second, policy.base_delay * 2);
        assert_eq!(third, policy.base_delay * 4);
        assert!(policy.delay_for(20, None, 1.0) <= policy.max_delay);
    }

    #[test]
    fn jitter_samples_the_whole_window() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay_for(3, None, 0.0), Duration::ZERO);
        assert_eq!(policy.delay_for(3, None, 1.0), policy.base_delay * 4);
        let middle = policy.delay_for(3, None, 0.5);
        assert!(middle > Duration::ZERO && middle < policy.base_delay * 4);
    }

    #[test]
    fn retry_after_is_honoured_but_capped() {
        let policy = RetryPolicy::default();
        let short = Duration::from_secs(2);
        assert_eq!(policy.delay_for(1, Some(short), 0.0), short);

        // A server asking for an hour must not hang the CLI for an hour.
        let hostile = Duration::from_secs(3600);
        assert_eq!(policy.delay_for(1, Some(hostile), 1.0), policy.max_delay);
    }

    #[test]
    fn a_single_attempt_policy_never_retries() {
        let policy = RetryPolicy {
            max_attempts: 1,
            ..RetryPolicy::default()
        };
        assert_eq!(
            policy.decide(RequestKind::Read, status(503), 1, Duration::ZERO, 1.0),
            Decision::Stop
        );
    }
}
