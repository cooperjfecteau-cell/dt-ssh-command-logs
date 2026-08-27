# dt-ssh-command-logs

A Dynatrace Extension 2.0 that connects to a Linux server over SSH, runs a command you
choose, and ingests the terminal output as log records in Grail.

It exists for the things that have no agent and no API: a vendor appliance, a hardened
host where you cannot install OneAgent, an air-gapped box reachable only from a jump
network, or a one-line health command whose output nobody has ever been able to alert on.

```
ActiveGate ──ssh──▶ Linux host ──stdout/stderr──▶ log records ──▶ Grail
```

| | |
|---|---|
| Extension name | `custom:ssh.command.logs` |
| Data source | Python (Extension 2.0) |
| Runs on | ActiveGate (remote activation) |
| Ingests | Log records, plus four self-monitoring metrics |
| Needs on the target | An SSH login and the command you want to run. No agent. |

## What lands in Dynatrace

Each output line becomes one log record. `uptime && df -h /` on `10.0.0.5` produces:

```
 14:32:09 up 27 days,  3:14,  2 users,  load average: 0.42, 0.31, 0.28
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   21G   27G  44% /
```

carrying these attributes:

| Attribute | Example | Why it is there |
|---|---|---|
| `log.source` | `linux.disk` | What you filter on. You choose it per endpoint. |
| `host.name` | `10.0.0.5` | Associates the record with the target host, not the ActiveGate. |
| `ssh.endpoint` | `web-01 disk` | The endpoint name from the monitoring configuration. |
| `ssh.command` | `df -h /` | The command, verbatim. |
| `ssh.exit_code` | `0` | Exit status of the whole run. |
| `ssh.stream` | `stdout` / `stderr` | Which stream the line came from. |
| `ssh.line` | `2` | Restores line order — every line of one run shares the capture timestamp. |
| `ssh.duration_ms` | `128.5` | Connect + run + read. |
| `ssh.user`, `ssh.host`, `ssh.port` | | Connection identity. |

Plus anything you add under **Additional log attributes** (`environment=prod`, `team=platform`).

Query them:

```
fetch logs
| filter log.source == "linux.disk"
| filter ssh.endpoint == "web-01 disk"
| sort timestamp desc, ssh.line asc
| fields timestamp, host.name, ssh.exit_code, content
```

Find runs that failed:

```
fetch logs
| filter isNotNull(ssh.exit_code) and ssh.exit_code != 0
| summarize count(), by: {ssh.endpoint, ssh.command, ssh.exit_code}
```

### Metrics

Four metrics come along for alerting on the command itself rather than its text, all
dimensioned by `endpoint`, `host` and `user`:

`ssh.command.exit_code`, `ssh.command.duration`, `ssh.command.output_lines`,
`ssh.command.success` (1 or 0).

`ssh.command.success` is the one to put a static-threshold anomaly detector on: it goes to
0 for a failed command *and* for a host that could not be reached at all.

## Install

1. Download `custom_ssh.command.logs-<version>.zip` from the
   [releases](../../releases), or build it yourself (below).
2. In Dynatrace, go to **Extensions ▸ Upload custom Extension 2.0** and upload the zip.
   A self-signed build also needs its CA certificate uploaded to
   **Settings ▸ Web and mobile monitoring ▸ Credential vault** as an
   *Extension signature verification* credential — see
   [signing](https://docs.dynatrace.com/docs/ingest-from/extensions/sign-extension).
3. Open the extension and **Add monitoring configuration**, scoped to the ActiveGate group
   that can reach your Linux hosts.

## Configure an endpoint

One endpoint is one command on one host on one schedule. Add as many as you need.

**Connection** — host, port, user, and one of three authentications:

- **Password** — stored in the Dynatrace credential vault, never written to a log record.
- **Private key file on the ActiveGate** — an absolute path readable by the ActiveGate
  service user. Preferred for production: the key never enters the settings store.
- **Private key pasted below** — the full PEM/OpenSSH key, held as a secret.

**Host key verification** defaults to **pinned SHA256 fingerprint**, and the first run of a
new endpoint is *expected* to fail:

```
web-01 disk: no expected host key fingerprint is configured. 10.0.0.5 presented
SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU (ssh-ed25519). Paste that value
into 'Expected host key fingerprint' after confirming it out of band.
```

Confirm that fingerprint independently — `ssh-keyscan -t ed25519 10.0.0.5 | ssh-keygen -lf -`
from a host you trust — then paste it in. From then on a changed host key stops the
connection instead of handing your credentials to whatever answered.

The alternatives are a `known_hosts` file on the ActiveGate, or **Accept any host key**,
which is offered for lab use and is exactly as unsafe as it sounds.

**Command** — runs through the login user's default shell, exactly as typed. Pipes,
`&&`, and redirection all work. Turn on **Allocate a pseudo-terminal** for commands that
refuse to run without a TTY; note that this merges stderr into stdout, the way it would in
your own terminal.

**Limits** — `Run every` (minutes), connect and command timeouts, `Maximum lines per run`,
`Maximum output bytes per run`. Hitting a limit ingests a `WARN` record saying so rather
than silently dropping the rest.

### Sizing the log volume

Ingest is billed by volume, and this extension will faithfully ingest whatever you point
it at. `journalctl -n 5000` every minute is 7.2 million records a day. Prefer a command
that has already done the filtering — `journalctl -p err --since -5min --no-pager`,
`systemctl --failed --no-legend` — and set the interval to the slowest one that still
answers your question.

## Security

- The account only needs permission to run your command. Give it a dedicated login and
  the narrowest shell you can; `command=` restrictions in `authorized_keys` work well.
- Credentials live in the Dynatrace credential vault and are never placed on a log record;
  a test asserts this.
- The command output is ingested verbatim. A command that prints a secret ingests that
  secret. Do not point this at `env`, `cat ~/.aws/credentials`, or similar.
- Anyone who can edit the monitoring configuration can run an arbitrary command on the
  target host as that user. Restrict who holds `settings:objects:write` for this schema.

## Build it yourself

Needs Python 3.10 or 3.14 — the two runtimes ActiveGate ships. Python 3.10 loses support
on 26 October 2026, so new work should target 3.14 (ActiveGate 1.333+).

```bash
python -m venv .venv
.venv/Scripts/activate          # or: source .venv/bin/activate
pip install "dt-extensions-sdk[cli]" paramiko pytest

dt-sdk gencerts                 # once, writes to ~/.dynatrace/certificates
dt-sdk build -e manylinux2014_x86_64 -p 3.10 -p 3.14
```

`dt-sdk` shells out to the `dt` CLI, so the venv's `Scripts`/`bin` directory has to be on
`PATH`, not just the interpreter.

That produces `dist/custom_ssh.command.logs-<version>.zip`, signed and ready to upload.
`-e manylinux2014_x86_64` is what makes it work on a Linux ActiveGate when you build on
Windows or macOS; drop `-p 3.10` if you only target 1.333+ and want a smaller package.

## Develop

The repository ships a real SSH server for development, so you never have to point work in
progress at a production host:

```bash
python tools/local_ssh_server.py     # 127.0.0.1:2222, user demo / demo-password
dt-sdk run                           # in another shell
```

`activation.json` already points at it. `dt-sdk run` prints every log record and metric it
would have sent, so you can see the exact payload without a tenant.

```bash
pytest                               # 42 tests
ruff check .
```

The tests run against that same SSH server on a loopback port — real handshake, real
authentication, real exec request — rather than a mocked paramiko. Host key pinning,
authentication failure, timeouts, truncation, and private key auth are all covered against
the actual protocol.

## Layout

```
extension/
  extension.yaml          extension name, version, python runtime, metric metadata
  activationSchema.json   the monitoring configuration UI
ssh_command_logs/
  __main__.py             scheduling, concurrency, ingest
  config.py               endpoint parsing and validation
  ssh_client.py           connect, run one command, read the output
  logs.py                 command output to log records
tests/
  ssh_test_server.py      in-process SSH server used by the tests and tools/
tools/
  local_ssh_server.py     runnable fake Linux host for dt-sdk run
```

## Limitations

- One command per endpoint. A shell one-liner covers most of what multiple commands would.
- No interactive sessions: no `sudo` password prompts (use `NOPASSWD` or a key with a
  forced command), no paging, no long-lived streams. `tail -f` will hit the command timeout.
- Output is captured after the command exits, so a long-running command ingests nothing
  until it finishes.
- x86-64 only as built. Add `-e manylinux2014_aarch64` for an ARM ActiveGate.

## License

MIT — see [LICENSE](LICENSE).
