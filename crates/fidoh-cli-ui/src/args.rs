//! Hand-rolled argument parsing (design D3: no external arg-parsing
//! crate — a three-subcommand, ~6-flag tool does not need one).
//!
//! Grammar:
//!
//! ```text
//! fidoh <command> [flags]
//!   list
//!   info   [--device <id>] [--budget <seconds>]
//!   assert --rp <rpId> [--allow <hex-id>]... [--first]
//!          [--budget <seconds>] [--demo]
//!   help | --help | -h
//! ```
//!
//! `--demo` (design D5) runs the assert ceremony against the in-process
//! soft token instead of hardware discovery.
//!
//! Parse failures are typed ([`ParseOutcome::Failed`]) with a
//! human-rendered usage message; the parser never panics, never reads
//! the environment, and never allocates beyond the arg strings.

use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

/// The default ceremony budget (seconds). One budget for the whole
/// ceremony — discovery, connect, probe, exchange (async-core D4); the
/// only duration a user reasons about (ceremony design A3).
pub const DEFAULT_BUDGET_SECS: u64 = 45;

/// A parsed, validated invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// `list`: enumerate every compiled-in transport.
    List,
    /// `info`: the mandatory getInfo probe, standalone.
    Info {
        /// Restrict discovery to the named device id (exact match);
        /// `None` probes the selection outcome over all transports.
        device: Option<String>,
        /// The single ceremony budget in seconds.
        budget_secs: u64,
    },
    /// `assert`: the full getAssertion ceremony.
    Assert(AssertArgs),
}

/// Validated `assert` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertArgs {
    /// The relying-party identifier (CTAP2.1 §6.2 request key 0x01) —
    /// required; there is no default RP.
    pub rp_id: String,
    /// Allow-list credential ids as hex strings (CTAP2.1 §6.2 key
    /// 0x03). Empty = resident-key flow (no allowList on the wire).
    pub allow: Vec<String>,
    /// `--first`: the explicit `First` selection policy opt-in
    /// (ceremony design A2: `First` must be chosen explicitly).
    pub first: bool,
    /// The single ceremony budget in seconds.
    pub budget_secs: u64,
    /// `--demo`: run the same ceremony against the in-process soft
    /// token (design D5); no hardware is touched.
    pub demo: bool,
}

/// A malformed flag occurrence, typed for the renderer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedFlag {
    /// The offending token as typed.
    pub token: String,
    /// What went wrong.
    pub reason: FlagReason,
}

/// Why a token was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagReason {
    /// No subcommand was given (or the first token was a flag).
    MissingCommand,
    /// The subcommand is not one of list/info/assert/help.
    UnknownCommand,
    /// `--rp` is mandatory for assert and was absent.
    MissingRp,
    /// A flag was given a value it does not take, or took a value it
    /// does not take (`--demo=x`), or is unknown.
    UnknownFlag,
    /// A value-taking flag lacked its value.
    MissingValue,
    /// `--budget` value is not a positive integer.
    BadBudget,
    /// An `--allow` value is not valid hex (or has odd length).
    BadHex,
}

/// The parse result: a valid invocation, a help request, or a typed
/// failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Ready to run.
    Parsed(Invocation),
    /// `help` / `--help` / `-h`: print usage, exit 0.
    Help,
    /// Rejected: the renderer prints usage plus the typed reason.
    Failed(FailedFlag),
}

impl FailedFlag {
    /// The one-line human message for this failure.
    pub fn message(&self) -> String {
        match self.reason {
            FlagReason::MissingCommand => String::from("a subcommand is required"),
            FlagReason::UnknownCommand => format!("unknown command '{}'", self.token),
            FlagReason::MissingRp => String::from("assert requires --rp <rpId>"),
            FlagReason::UnknownFlag => format!("unknown flag '{}'", self.token),
            FlagReason::MissingValue => format!("flag '{}' needs a value", self.token),
            FlagReason::BadBudget => {
                format!("'{}' is not a positive integer of seconds", self.token)
            }
            FlagReason::BadHex => format!("'{}' is not valid hex bytes", self.token),
        }
    }
}

/// The multi-line usage text (also the `help` output).
pub fn usage() -> String {
    String::from(
        "fidoh — FIDO2 / CTAP2 token tool\n\
         \n\
         USAGE:\n\
         \x20   fidoh list\n\
         \x20   fidoh info [--device <id>] [--budget <seconds>]\n\
         \x20   fidoh assert --rp <rpId> [--allow <hex-id>]... [--first]\n\
         \x20                [--budget <seconds>] [--demo]\n\
         \n\
         COMMANDS:\n\
         \x20   list    enumerate every transport with typed diagnostics\n\
         \x20   info    authenticatorGetInfo capability probe (CTAP2.1 §6.4)\n\
         \x20   assert  getAssertion ceremony (CTAP2.1 §6.2)\n\
         \n\
         FLAGS (info):\n\
         \x20   --device <id>  only consider the named device\n\
         \x20   --budget <s>   total ceremony budget in seconds (default 45)\n\
         \n\
         FLAGS (assert):\n\
         \x20   --rp <rpId>    relying-party id (required)\n\
         \x20   --allow <hex>  credential id to restrict the request to (repeatable)\n\
         \x20   --first        pick the first enumerated device (default: fail on\n\
         \x20                  multiple candidates)\n\
         \x20   --budget <s>   total ceremony budget in seconds (default 45)\n\
         \x20   --demo         run against the in-process soft token, no hardware",
    )
}

/// Parse `args` (already split, `argv[1..]` style).
pub fn parse(args: &[String]) -> ParseOutcome {
    let Some((first, rest)) = args.split_first() else {
        return ParseOutcome::Failed(FailedFlag {
            token: String::new(),
            reason: FlagReason::MissingCommand,
        });
    };
    match first.as_str() {
        "help" | "--help" | "-h" => return ParseOutcome::Help,
        "list" => {
            return if rest.is_empty() {
                ParseOutcome::Parsed(Invocation::List)
            } else {
                ParseOutcome::Failed(FailedFlag {
                    token: rest[0].clone(),
                    reason: FlagReason::UnknownFlag,
                })
            };
        }
        "info" => return parse_info(rest),
        "assert" => return parse_assert(rest),
        _ => {}
    }
    ParseOutcome::Failed(FailedFlag {
        token: first.to_string(),
        reason: FlagReason::UnknownCommand,
    })
}

fn parse_info(rest: &[String]) -> ParseOutcome {
    let mut device = None;
    let mut budget = DEFAULT_BUDGET_SECS;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--device" => {
                let Some(value) = rest.get(i + 1) else {
                    return fail(rest[i].clone(), FlagReason::MissingValue);
                };
                device = Some(value.clone());
                i += 2;
            }
            "--budget" => {
                let Some(value) = rest.get(i + 1) else {
                    return fail(rest[i].clone(), FlagReason::MissingValue);
                };
                match parse_budget(value) {
                    Some(b) => budget = b,
                    None => return fail(value.clone(), FlagReason::BadBudget),
                }
                i += 2;
            }
            other => return fail(other.to_string(), FlagReason::UnknownFlag),
        }
    }
    ParseOutcome::Parsed(Invocation::Info {
        device,
        budget_secs: budget,
    })
}

fn parse_assert(rest: &[String]) -> ParseOutcome {
    let mut out = AssertArgs {
        rp_id: String::new(),
        allow: Vec::new(),
        first: false,
        budget_secs: DEFAULT_BUDGET_SECS,
        demo: false,
    };
    let mut rp_seen = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--rp" => {
                let Some(value) = rest.get(i + 1) else {
                    return fail(rest[i].clone(), FlagReason::MissingValue);
                };
                out.rp_id = value.clone();
                rp_seen = true;
                i += 2;
            }
            "--allow" => {
                let Some(value) = rest.get(i + 1) else {
                    return fail(rest[i].clone(), FlagReason::MissingValue);
                };
                if decode_hex(value).is_none() {
                    return fail(value.clone(), FlagReason::BadHex);
                }
                // Normalize: lowercase, no 0x prefix (decode_hex strips
                // it at consume time too; the stored form is canonical).
                let body = value.strip_prefix("0x").unwrap_or(value);
                out.allow.push(body.to_ascii_lowercase());
                i += 2;
            }
            "--first" => {
                out.first = true;
                i += 1;
            }
            "--budget" => {
                let Some(value) = rest.get(i + 1) else {
                    return fail(rest[i].clone(), FlagReason::MissingValue);
                };
                match parse_budget(value) {
                    Some(b) => out.budget_secs = b,
                    None => return fail(value.clone(), FlagReason::BadBudget),
                }
                i += 2;
            }
            "--demo" => {
                out.demo = true;
                i += 1;
            }
            other => return fail(other.to_string(), FlagReason::UnknownFlag),
        }
    }
    if !rp_seen {
        return fail(String::from("--rp"), FlagReason::MissingRp);
    }
    ParseOutcome::Parsed(Invocation::Assert(out))
}

fn fail(token: String, reason: FlagReason) -> ParseOutcome {
    ParseOutcome::Failed(FailedFlag { token, reason })
}

/// `--budget` values: positive integers, seconds.
fn parse_budget(value: &str) -> Option<u64> {
    let n: u64 = value.parse().ok()?;
    (n > 0).then_some(n)
}

/// Lowercase hex decode (even length, both cases accepted).
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    if body.is_empty() || body.len() % 2 != 0 {
        return None;
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn list_parses() {
        assert_eq!(
            parse(&argv(&["list"])),
            ParseOutcome::Parsed(Invocation::List)
        );
    }

    #[test]
    fn info_defaults_and_flags() {
        assert_eq!(
            parse(&argv(&["info"])),
            ParseOutcome::Parsed(Invocation::Info {
                device: None,
                budget_secs: DEFAULT_BUDGET_SECS
            })
        );
        assert_eq!(
            parse(&argv(&[
                "info",
                "--device",
                "/dev/hidraw0",
                "--budget",
                "10"
            ])),
            ParseOutcome::Parsed(Invocation::Info {
                device: Some(String::from("/dev/hidraw0")),
                budget_secs: 10
            })
        );
    }

    #[test]
    fn assert_requires_rp() {
        assert_eq!(
            parse(&argv(&["assert"])),
            ParseOutcome::Failed(FailedFlag {
                token: String::from("--rp"),
                reason: FlagReason::MissingRp
            })
        );
    }

    #[test]
    fn assert_parses_full_surface() {
        assert_eq!(
            parse(&argv(&[
                "assert",
                "--rp",
                "example.com",
                "--allow",
                "AABB",
                "--allow",
                "0xccdd",
                "--first",
                "--budget",
                "9",
                "--demo"
            ])),
            ParseOutcome::Parsed(Invocation::Assert(AssertArgs {
                rp_id: String::from("example.com"),
                allow: vec![String::from("aabb"), String::from("ccdd")],
                first: true,
                budget_secs: 9,
                demo: true,
            }))
        );
    }

    #[test]
    fn bad_hex_and_budget_typed() {
        assert_eq!(
            parse(&argv(&["assert", "--rp", "r", "--allow", "zz"])),
            ParseOutcome::Failed(FailedFlag {
                token: String::from("zz"),
                reason: FlagReason::BadHex
            })
        );
        assert_eq!(
            parse(&argv(&["assert", "--rp", "r", "--budget", "0"])),
            ParseOutcome::Failed(FailedFlag {
                token: String::from("0"),
                reason: FlagReason::BadBudget
            })
        );
    }

    #[test]
    fn help_and_errors() {
        assert_eq!(parse(&argv(&["help"])), ParseOutcome::Help);
        assert_eq!(
            parse(&argv(&[])),
            ParseOutcome::Failed(FailedFlag {
                token: String::new(),
                reason: FlagReason::MissingCommand
            })
        );
        assert!(matches!(
            parse(&argv(&["frobnicate"])),
            ParseOutcome::Failed(FailedFlag {
                reason: FlagReason::UnknownCommand,
                ..
            })
        ));
        // usage is non-trivial and names all three commands
        let u = usage();
        assert!(u.contains("list") && u.contains("info") && u.contains("assert"));
    }
}
