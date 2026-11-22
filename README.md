# sshdlint

Reads an OpenSSH server config (`sshd_config`) and lists the risky settings in it.

## Install

```
cargo install --git https://github.com/subnetsmith/sshdlint
```

## Use

Check a config file (with no file given it reads `/etc/ssh/sshd_config`):

```
$ sshdlint examples/risky_sshd_config
HIGH    line 4    PermitRootLogin yes: root can log in with a password; use 'no' or 'prohibit-password'
HIGH    line 15   PermitEmptyPasswords yes (in Match block at line 14): accounts with an empty password can log in
MEDIUM  line 5    PasswordAuthentication yes: passwords can be guessed by bots; prefer keys and set this to 'no'
MEDIUM  line 8    Ciphers +aes128-cbc,3des-cbc: weak algorithms: aes128-cbc, 3des-cbc
MEDIUM  line 9    MACs hmac-sha2-256,hmac-md5: weak algorithms: hmac-md5
LOW     line 2    Include /etc/ssh/sshd_config.d/*.conf was not followed; check those files too, they can override this one
LOW     line 6    MaxAuthTries 10: 10 password tries per connection; 3 or 4 slows guessing
LOW     line 7    X11Forwarding yes: X11 forwarding lets a compromised server reach your desktop; turn off if unused
LOW     line 12   PasswordAuthentication set again, but sshd keeps the first value (line 5); this line does nothing
9 finding(s): 2 high, 3 medium, 4 low
```

Show only the worst problems:

```
$ sshdlint --min high examples/risky_sshd_config
HIGH    line 4    PermitRootLogin yes: root can log in with a password; use 'no' or 'prohibit-password'
HIGH    line 15   PermitEmptyPasswords yes (in Match block at line 14): accounts with an empty password can log in
2 finding(s): 2 high, 0 medium, 0 low
```

A clean config:

```
$ sshdlint examples/hardened_sshd_config
0 finding(s): 0 high, 0 medium, 0 low
```

Read from stdin with `-`:

```
$ printf 'KexAlgorithms diffie-hellman-group1-sha1\nPasswordAuthentication=no\n' | sshdlint -
MEDIUM  line 1    KexAlgorithms diffie-hellman-group1-sha1: weak algorithms: diffie-hellman-group1-sha1
1 finding(s): 0 high, 1 medium, 0 low
```

Exit codes: `0` nothing found, `1` findings at or above `--min`, `2` error.
So `sshdlint --min high` can stop a deploy script or CI job.

## Why it's useful

sshd keeps the **first** value it reads for most settings. Adding
`PasswordAuthentication no` at the bottom of the file often does nothing, and
sshdlint points that out. It also catches root login, empty passwords and weak
ciphers before a bot on the internet finds them.

## Limits

- It does not follow `Include` lines. It tells you to check those files yourself.
- Settings inside `Match` blocks are checked, but it does not work out which
  users or addresses a block matches.
- It only reads the file. It does not connect to a server or check what sshd
  is actually running (`sshd -T` shows that).
- The checks cover common mistakes, not every sshd option.
