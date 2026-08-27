//! Interactive prompting, and the rules for when it is allowed.
//!
//! Two properties matter more than the prompts themselves:
//!
//! * **never block on a stdin that will never arrive.** Under a pipe, in CI, or
//!   in a container with no terminal, a prompt is a hang. Every entry point
//!   here checks first and returns a specific error naming the flag that would
//!   have supplied the answer.
//! * **never choose the permissive option silently.** A missing answer is an
//!   error, not a default. Nothing here can select `0.0.0.0/0`, delete a boot
//!   volume, or confirm a plan on the user's behalf.
//!
//! CLAUDE.md rules out a full-screen TUI for v1, so this is prompts only.

use std::io::IsTerminal as _;

use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use crate::error::{Error, Result};

/// Whether stdin is attached to a terminal.
///
/// Also honours the widely-observed `CI` convention: an automated run should
/// never be prompted even when a pseudo-terminal happens to be allocated.
#[must_use]
pub fn stdin_is_a_terminal() -> bool {
    if std::env::var_os("CI").is_some() {
        return false;
    }
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The error returned when a prompt is needed but impossible.
///
/// `flag` names the command-line option that would have supplied the answer,
/// so a script author is told exactly what to add.
#[must_use]
pub fn not_interactive(what: &str, flag: &str) -> Error {
    Error::invalid_input(format!("{what} was not supplied and cannot be asked for"))
        .with_context(
            "this run has no terminal attached, so oci-free will not prompt; it also will not \
             guess, because the safe answer and the convenient one are not always the same",
        )
        .with_remediation(format!("pass {flag}"))
}

/// Ask a yes/no question.
///
/// `default_yes` is deliberately not offered: every call site in this codebase
/// is confirming a mutation, and a mutation prompt must default to no.
pub fn confirm(prompt: &str) -> Result<bool> {
    if !stdin_is_a_terminal() {
        return Err(not_interactive("confirmation", "--yes"));
    }
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(prompt_failed)
}

/// Ask the user to choose one of `options`.
///
/// Returns the index of the chosen entry.
pub fn select(prompt: &str, options: &[String], default_index: usize, flag: &str) -> Result<usize> {
    if options.is_empty() {
        return Err(Error::not_found(format!(
            "there is nothing to choose for {prompt}"
        )));
    }
    if options.len() == 1 {
        return Ok(0);
    }
    if !stdin_is_a_terminal() {
        return Err(not_interactive(prompt, flag));
    }
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(options)
        .default(default_index.min(options.len() - 1))
        .interact()
        .map_err(prompt_failed)
}

/// Ask for a line of text.
pub fn input(prompt: &str, default: Option<&str>, flag: &str) -> Result<String> {
    if !stdin_is_a_terminal() {
        return Err(not_interactive(prompt, flag));
    }
    let theme = ColorfulTheme::default();
    let mut builder = Input::<String>::with_theme(&theme).with_prompt(prompt);
    if let Some(default) = default {
        builder = builder.default(default.to_owned());
    }
    builder.interact_text().map_err(prompt_failed)
}

fn prompt_failed(error: dialoguer::Error) -> Error {
    Error::invalid_input("the prompt could not be read")
        .with_context(error.to_string())
        .with_remediation("re-run with the choice supplied on the command line")
}

#[cfg(test)]
mod tests {
    use super::not_interactive;
    use crate::error::ErrorKind;

    /// The whole point of the module: a missing answer in a non-interactive run
    /// is an error that names the flag, never a guess.
    #[test]
    fn a_missing_answer_names_the_flag_that_supplies_it() {
        let error = not_interactive("the ingress source", "--source");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.message().contains("the ingress source"));
        assert!(error.remediation().contains("--source"));
        assert!(error.context().expect("context").contains("will not guess"));
    }

    /// Under a test harness there is no terminal, which is exactly the
    /// condition the guard exists for. Asserting it here documents that command
    /// tests can never accidentally block on a prompt.
    #[test]
    fn tests_never_run_interactively() {
        assert!(
            !super::stdin_is_a_terminal(),
            "the test harness must never be treated as interactive"
        );
    }
}
