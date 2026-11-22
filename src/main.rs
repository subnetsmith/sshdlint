use sshdlint::{audit, read_capped, Severity};
use std::fs::File;
use std::process::ExitCode;

const USAGE: &str = "usage: sshdlint [--min low|medium|high] [FILE|-]
  FILE defaults to /etc/ssh/sshd_config; '-' reads stdin.
exit codes: 0 nothing found, 1 findings at or above --min, 2 error";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("sshdlint: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let mut min = Severity::Low;
    let mut path: Option<String> = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "--min" => {
                let v = it.next().ok_or("--min needs a value")?;
                min = Severity::parse(&v).ok_or(format!("bad --min '{v}'\n{USAGE}"))?;
            }
            _ if a.starts_with("--") => return Err(format!("unknown option '{a}'\n{USAGE}")),
            _ if path.is_none() => path = Some(a),
            _ => return Err(format!("only one file at a time\n{USAGE}")),
        }
    }
    let path = path.unwrap_or_else(|| "/etc/ssh/sshd_config".into());

    let text = if path == "-" {
        read_capped(std::io::stdin().lock())?
    } else {
        // Only read regular files: a directory or device would hang or mislead.
        let meta = std::fs::metadata(&path).map_err(|e| format!("{path}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{path}: not a regular file"));
        }
        let file = File::open(&path).map_err(|e| format!("{path}: {e}"))?;
        read_capped(file).map_err(|e| format!("{path}: {e}"))?
    };

    let findings: Vec<_> = audit(&text).into_iter().filter(|f| f.severity >= min).collect();
    for f in &findings {
        let line = f.line.map_or("-".to_string(), |n| format!("line {n}"));
        println!("{:<7} {:<9} {}", f.severity, line, f.message);
    }
    let count = |s| findings.iter().filter(|f| f.severity == s).count();
    println!(
        "{} finding(s): {} high, {} medium, {} low",
        findings.len(),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low)
    );
    Ok(if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
