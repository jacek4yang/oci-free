//! Shared test support.
//!
//! Compiled only under `cfg(test)`, so nothing here can reach a release build.
//! The centrepiece is [`mock_oci::MockOci`], an in-process HTTPS server that
//! lets command and adapter tests exercise the real transport — signing,
//! retries, pagination, error decoding — without talking to Oracle.

pub mod mock_oci;
