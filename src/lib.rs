//! sshdlint: read an OpenSSH server config (sshd_config) and flag risky settings.
//!
//! The parser follows two sshd rules that trip people up:
//! 1. Keywords are case-insensitive and may be written `Key value` or `Key=value`.
//! 2. For most keywords sshd keeps the FIRST value it sees. A line added at the
//!    bottom of the file does not override an earlier one, so we report that.

use std::fmt;
use std::io::Read;

/// Biggest config we will read. Real sshd_config files are a few KB; the cap
/// stops a wrong path (a huge log, a device) from eating memory.
pub const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // pad (not write_str) so "{:<7}" column widths work.
        f.pad(match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        })
    }
}

/// One `Keyword value` line from the file.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub line: usize,
    /// Keyword as written, for messages.
    pub key: String,
    pub value: String,
    /// Line of the `Match` block this sits in, if any.
    pub match_line: Option<usize>,
}

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    /// None when the problem is a missing setting (the default applies).
    pub line: Option<usize>,
    pub message: String,
}

/// Split the file into directives. Comments and blank lines are dropped.
pub fn parse(text: &str) -> Vec<Directive> {
    let mut out = Vec::new();
    let mut match_line = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The keyword ends at the first space, tab or '='.
        let end = line
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(line.len());
        let key = &line[..end];
        let rest = line[end..].trim_start();
        let value = rest.strip_prefix('=').unwrap_or(rest).trim();
        if key.eq_ignore_ascii_case("match") {
            // Everything after a Match line belongs to it, until the next Match.
            match_line = Some(i + 1);
            continue;
        }
        out.push(Directive {
            line: i + 1,
            key: key.to_string(),
            value: value.to_string(),
            match_line,
        });
    }
    out
}

/// Weak algorithm names. Matching on substrings catches every variant
/// (aes128-cbc, aes256-cbc, hmac-md5-96, ...).
const WEAK_CIPHERS: &[&str] = &["cbc", "3des", "arcfour", "blowfish", "cast128"];
const WEAK_MACS: &[&str] = &["md5", "-96", "hmac-sha1", "umac-64"];
const WEAK_KEX: &[&str] = &["group1-sha1", "group14-sha1", "group-exchange-sha1"];

fn weak_algs(value: &str, weak: &[&str]) -> Vec<String> {
    // A leading '-' removes algorithms from the default list, which can only
    // make things safer. '+' and '^' add to it, so those still get checked.
    if value.starts_with('-') {
        return Vec::new();
    }
    value
        .trim_start_matches(['+', '^'])
        .split(',')
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| weak.iter().any(|w| a.contains(w)))
        .collect()
}

/// Judge one keyword/value pair on its own. Returns None if it looks fine.
fn check(key: &str, value: &str) -> Option<(Severity, String)> {
    let v = value.to_ascii_lowercase();
    let yes = v == "yes";
    match key.to_ascii_lowercase().as_str() {
        "permitrootlogin" if yes => Some((
            Severity::High,
            "root can log in with a password; use 'no' or 'prohibit-password'".into(),
        )),
        "permitemptypasswords" if yes => Some((
            Severity::High,
            "accounts with an empty password can log in".into(),
        )),
        "protocol" if v.contains('1') => Some((
            Severity::High,
            "SSH protocol 1 is broken; modern sshd ignores this line, remove it".into(),
        )),
        "passwordauthentication" if yes => Some((
            Severity::Medium,
            "passwords can be guessed by bots; prefer keys and set this to 'no'".into(),
        )),
        "permituserenvironment" if v != "no" => Some((
            Severity::Medium,
            "users can set environment variables (e.g. LD_PRELOAD) at login".into(),
        )),
        "hostbasedauthentication" if yes => Some((
            Severity::Medium,
            "trusts other hosts' word for who a user is".into(),
        )),
        "ciphers" | "macs" | "kexalgorithms" => {
            let list = match key.to_ascii_lowercase().as_str() {
                "ciphers" => WEAK_CIPHERS,
                "macs" => WEAK_MACS,
                _ => WEAK_KEX,
            };
            let weak = weak_algs(value, list);
            (!weak.is_empty())
                .then(|| (Severity::Medium, format!("weak algorithms: {}", weak.join(", "))))
        }
        "maxauthtries" => match value.parse::<u32>() {
            Ok(n) if n > 4 => Some((
                Severity::Low,
                format!("{n} password tries per connection; 3 or 4 slows guessing"),
            )),
            Ok(_) => None,
            // sshd refuses to start on a bad number, which locks you out.
            Err(_) => Some((Severity::Medium, format!("'{value}' is not a number; sshd will not start"))),
        },
        "x11forwarding" if yes => Some((
            Severity::Low,
            "X11 forwarding lets a compromised server reach your desktop; turn off if unused".into(),
        )),
        "gatewayports" if v != "no" => Some((
            Severity::Low,
            "forwarded ports can be opened to the whole network".into(),
        )),
        "loglevel" if matches!(v.as_str(), "quiet" | "fatal" | "error") => Some((
            Severity::Low,
            "logging is too quiet to see failed logins; use INFO or VERBOSE".into(),
        )),
        _ => None,
    }
}

/// Check a whole config. Results are sorted, worst first.
pub fn audit(text: &str) -> Vec<Finding> {
    let directives = parse(text);
    let mut findings = Vec::new();
    // Global keyword (lowercase) -> line where sshd took its value from.
    let mut first_seen: Vec<(String, usize)> = Vec::new();

    for d in &directives {
        let lower = d.key.to_ascii_lowercase();
        if lower == "include" {
            findings.push(Finding {
                severity: Severity::Low,
                line: Some(d.line),
                message: format!(
                    "Include {} was not followed; check those files too, they can override this one",
                    d.value
                ),
            });
            continue;
        }
        if d.match_line.is_none() {
            if let Some((_, first)) = first_seen.iter().find(|(k, _)| *k == lower) {
                // The earlier value is the live one and already got judged.
                findings.push(Finding {
                    severity: Severity::Low,
                    line: Some(d.line),
                    message: format!(
                        "{} set again, but sshd keeps the first value (line {first}); this line does nothing",
                        d.key
                    ),
                });
                continue;
            }
            first_seen.push((lower.clone(), d.line));
        }
        if let Some((severity, msg)) = check(&d.key, &d.value) {
            let place = match d.match_line {
                Some(m) => format!(" (in Match block at line {m})"),
                None => String::new(),
            };
            findings.push(Finding {
                severity,
                line: Some(d.line),
                message: format!("{} {}{place}: {msg}", d.key, d.value),
            });
        }
    }

    // OpenSSH's built-in default is PasswordAuthentication yes.
    if !first_seen.iter().any(|(k, _)| k == "passwordauthentication") {
        findings.push(Finding {
            severity: Severity::Medium,
            line: None,
            message: "PasswordAuthentication not set: OpenSSH defaults to yes".into(),
        });
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));
    findings
}

/// Read config text with a size cap. Rejects non-UTF-8 input instead of guessing.
pub fn read_capped(reader: impl Read) -> Result<String, String> {
    let mut buf = Vec::new();
    reader
        .take(MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    if buf.len() as u64 > MAX_BYTES {
        return Err(format!("input is bigger than {MAX_BYTES} bytes; is this really an sshd_config?"));
    }
    String::from_utf8(buf).map_err(|_| "input is not UTF-8 text".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn messages(text: &str) -> Vec<String> {
        audit(text).into_iter().map(|f| f.message).collect()
    }

    #[test]
    fn parses_space_equals_and_case() {
        let d = parse("  PermitRootLogin   yes\nport=2222\n# comment\n\nMaxAuthTries = 3\n");
        assert_eq!(d.len(), 3);
        assert_eq!((d[0].key.as_str(), d[0].value.as_str(), d[0].line), ("PermitRootLogin", "yes", 1));
        assert_eq!((d[1].key.as_str(), d[1].value.as_str()), ("port", "2222"));
        assert_eq!((d[2].value.as_str(), d[2].line), ("3", 5));
    }

    #[test]
    fn root_login_yes_is_high() {
        let f = audit("PasswordAuthentication no\npermitrootlogin YES\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].line, Some(2));
    }

    #[test]
    fn safe_config_is_clean() {
        let text = "PermitRootLogin prohibit-password\nPasswordAuthentication no\n\
                    MaxAuthTries 3\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n";
        assert!(audit(text).is_empty(), "{:?}", audit(text));
    }

    #[test]
    fn first_value_wins() {
        // The classic mistake: appending 'no' after the distro's 'yes'.
        let f = audit("PasswordAuthentication yes\nPasswordAuthentication no\n");
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].line, Some(1));
        assert!(f[1].message.contains("keeps the first value (line 1)"));
    }

    #[test]
    fn match_blocks_are_checked_separately() {
        let text = "PasswordAuthentication no\nX11Forwarding no\nMatch User guest\n  X11Forwarding yes\n";
        let m = messages(text);
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("in Match block at line 3"), "{m:?}");
    }

    #[test]
    fn missing_password_auth_uses_default() {
        let f = audit("Port 22\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, None);
    }

    #[test]
    fn weak_algorithms_found_and_minus_ignored() {
        assert_eq!(weak_algs("+aes128-cbc,aes256-gcm@openssh.com", WEAK_CIPHERS), vec!["aes128-cbc"]);
        assert_eq!(weak_algs("hmac-sha2-256,hmac-sha1", WEAK_MACS), vec!["hmac-sha1"]);
        assert!(weak_algs("-aes128-cbc", WEAK_CIPHERS).is_empty());
        // sha2 must not be caught by the "hmac-sha1" rule.
        assert!(weak_algs("hmac-sha2-512-etm@openssh.com", WEAK_MACS).is_empty());
    }

    #[test]
    fn bad_number_flagged() {
        let m = messages("PasswordAuthentication no\nMaxAuthTries lots\n");
        assert!(m[0].contains("not a number"), "{m:?}");
    }

    #[test]
    fn read_capped_rejects_big_and_binary_input() {
        let big = vec![b'#'; MAX_BYTES as usize + 1];
        assert!(read_capped(&big[..]).unwrap_err().contains("bigger"));
        assert!(read_capped(&[0xff, 0xfe, 0x00][..]).unwrap_err().contains("UTF-8"));
        assert_eq!(read_capped(&b"Port 22\n"[..]).unwrap(), "Port 22\n");
    }
}
