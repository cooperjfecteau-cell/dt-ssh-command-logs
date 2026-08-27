"""The SSH half of the extension: connect, run one command, bring back its terminal output.

Kept free of any Dynatrace imports so it can be exercised against a real SSH server in the
test suite without an EEC or a tenant.
"""

from __future__ import annotations

import base64
import hashlib
import io
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import paramiko

from .config import (
    AUTH_KEY_CONTENT,
    AUTH_KEY_FILE,
    AUTH_PASSWORD,
    HOST_KEY_ACCEPT_ANY,
    HOST_KEY_KNOWN_HOSTS,
    EndpointConfig,
)

# Poll interval while waiting on channel data. Small enough that a fast command is not
# noticeably delayed, large enough that a long-running one does not spin a core.
_POLL_SECONDS = 0.02

# After the remote side reports an exit status there can still be bytes in flight. Wait one
# grace period with empty buffers before declaring the output complete.
_DRAIN_GRACE_SECONDS = 0.05

_READ_CHUNK = 64 * 1024


class SshError(Exception):
    """Base class for every failure that stops a command from producing output."""


class SshConnectError(SshError):
    """The TCP connection or SSH handshake did not complete."""


class SshAuthError(SshError):
    """The server rejected the credentials."""


class SshHostKeyError(SshError):
    """The host key did not match what the configuration expects."""


class SshCommandTimeoutError(SshError):
    """The command was still running when its timeout elapsed."""


@dataclass
class CommandResult:
    """Everything one command run produced, ready to be turned into log records."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: float = 0.0
    truncated: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    host_key_fingerprint: str = ""

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


def fingerprint_of(key: paramiko.PKey) -> str:
    """SHA256 fingerprint in the form OpenSSH prints (unpadded base64)."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class _PinnedFingerprintPolicy(paramiko.MissingHostKeyPolicy):
    """Accept exactly one host key, identified by its SHA256 fingerprint.

    An unset expected fingerprint is not treated as "accept anything": it fails with the
    fingerprint that was actually presented, which is how an operator learns the value to
    paste into the monitoring configuration without shell access to the ActiveGate.
    """

    def __init__(self, expected: str, endpoint_name: str):
        self._expected = expected
        self._endpoint_name = endpoint_name

    def missing_host_key(self, client, hostname, key):  # noqa: ARG002
        actual = fingerprint_of(key)
        if not self._expected:
            msg = (
                f"{self._endpoint_name}: no expected host key fingerprint is configured. "
                f"{hostname} presented {actual} ({key.get_name()}). Paste that value into "
                f"'Expected host key fingerprint' after confirming it out of band."
            )
            raise SshHostKeyError(msg)
        if actual != self._expected:
            msg = (
                f"{self._endpoint_name}: host key mismatch for {hostname}. Expected "
                f"{self._expected}, got {actual} ({key.get_name()}). Either the host was "
                f"rebuilt or the connection is being intercepted."
            )
            raise SshHostKeyError(msg)


class _KnownHostsPolicy(paramiko.MissingHostKeyPolicy):
    """Reject any host that is absent from known_hosts, naming the key it offered."""

    def __init__(self, endpoint_name: str, known_hosts_path: str):
        self._endpoint_name = endpoint_name
        self._known_hosts_path = known_hosts_path or "the ActiveGate user's known_hosts"

    def missing_host_key(self, client, hostname, key):  # noqa: ARG002
        msg = (
            f"{self._endpoint_name}: {hostname} is not in {self._known_hosts_path}. It "
            f"presented {fingerprint_of(key)} ({key.get_name()}). Add the host to that file, "
            f"or switch to pinned fingerprint verification."
        )
        raise SshHostKeyError(msg)


def run_command(config: EndpointConfig) -> CommandResult:
    """Connect, run ``config.command`` once, and return its output.

    Raises:
        SshHostKeyError, SshAuthError, SshConnectError, SshCommandTimeoutError: all with a
            message written to be shown to whoever configured the endpoint.
    """
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()

    client = paramiko.SSHClient()
    try:
        _apply_host_key_policy(client, config)
        _connect(client, config)

        transport = client.get_transport()
        fingerprint = fingerprint_of(transport.get_remote_server_key()) if transport else ""
        stdout, stderr, exit_code, truncated = _exec(transport, config)

        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=(time.monotonic() - started) * 1000,
            truncated=truncated,
            started_at=started_at,
            host_key_fingerprint=fingerprint,
        )
    finally:
        client.close()


def _apply_host_key_policy(client: paramiko.SSHClient, config: EndpointConfig) -> None:
    mode = config.host_key_verification

    if mode == HOST_KEY_ACCEPT_ANY:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return

    if mode == HOST_KEY_KNOWN_HOSTS:
        try:
            if config.known_hosts_path:
                client.load_host_keys(config.known_hosts_path)
            else:
                client.load_system_host_keys()
        except OSError as exception:
            msg = f"{config.name}: cannot read known_hosts: {exception}"
            raise SshHostKeyError(msg) from exception
        client.set_missing_host_key_policy(_KnownHostsPolicy(config.name, config.known_hosts_path))
        return

    # Pinned mode deliberately loads no known_hosts, so the policy is always consulted and
    # a stale system entry cannot silently override the pin.
    client.set_missing_host_key_policy(_PinnedFingerprintPolicy(config.host_key_fingerprint, config.name))


def _connect(client: paramiko.SSHClient, config: EndpointConfig) -> None:
    kwargs = {
        "hostname": config.host,
        "port": config.port,
        "username": config.username,
        "timeout": config.connect_timeout_seconds,
        "banner_timeout": config.connect_timeout_seconds,
        "auth_timeout": config.connect_timeout_seconds,
        # The ActiveGate service account may have its own keys and agent; never let them
        # leak into an endpoint that is configured for different credentials.
        "allow_agent": False,
        "look_for_keys": False,
    }

    if config.auth_type == AUTH_PASSWORD:
        kwargs["password"] = config.password
    elif config.auth_type == AUTH_KEY_FILE:
        kwargs["key_filename"] = config.private_key_path
        if config.private_key_passphrase:
            kwargs["passphrase"] = config.private_key_passphrase
    elif config.auth_type == AUTH_KEY_CONTENT:
        kwargs["pkey"] = _load_private_key(config)

    try:
        client.connect(**kwargs)
    except SshError:
        # Raised from inside the host key policy; already carries a good message.
        raise
    except paramiko.BadHostKeyException as exception:
        msg = (
            f"{config.name}: known_hosts has a different key for {config.host}. Expected "
            f"{fingerprint_of(exception.expected_key)}, got {fingerprint_of(exception.key)}."
        )
        raise SshHostKeyError(msg) from exception
    except paramiko.AuthenticationException as exception:
        msg = f"{config.name}: authentication failed for {config.target} ({exception})"
        raise SshAuthError(msg) from exception
    except paramiko.SSHException as exception:
        msg = f"{config.name}: SSH handshake with {config.target} failed: {exception}"
        raise SshConnectError(msg) from exception
    except OSError as exception:
        msg = f"{config.name}: cannot reach {config.target}: {exception}"
        raise SshConnectError(msg) from exception


def _load_private_key(config: EndpointConfig) -> paramiko.PKey:
    """Parse a pasted private key, trying each key type paramiko supports."""
    passphrase = config.private_key_passphrase or None
    last_error: Exception | None = None

    for class_name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        key_class = getattr(paramiko, class_name, None)
        if key_class is None:
            continue
        try:
            return key_class.from_private_key(io.StringIO(config.private_key_content), password=passphrase)
        except paramiko.SSHException as exception:
            last_error = exception

    msg = (
        f"{config.name}: the pasted private key could not be parsed. Check that the whole "
        f"key was pasted including its BEGIN and END lines, and that the passphrase is "
        f"correct ({last_error})"
    )
    raise SshAuthError(msg) from last_error


def _exec(transport, config: EndpointConfig) -> tuple[str, str, int | None, bool]:
    """Run the command on a fresh session channel and drain both output streams."""
    if transport is None:
        msg = f"{config.name}: the SSH transport closed before the command could start"
        raise SshConnectError(msg)

    try:
        channel = transport.open_session(timeout=config.connect_timeout_seconds)
    except paramiko.SSHException as exception:
        msg = f"{config.name}: could not open a session channel on {config.target}: {exception}"
        raise SshConnectError(msg) from exception

    stdout = bytearray()
    stderr = bytearray()
    truncated = False

    try:
        channel.settimeout(config.command_timeout_seconds)
        if config.use_pty:
            channel.get_pty()
        channel.exec_command(config.command)
        # Nothing is ever written to the command's stdin; closing it stops commands that
        # read from stdin from hanging until the timeout.
        channel.shutdown_write()

        deadline = time.monotonic() + config.command_timeout_seconds
        while True:
            read_any = _drain(channel, stdout, stderr)

            if len(stdout) + len(stderr) > config.max_output_bytes:
                truncated = True
                break

            if channel.exit_status_ready() and not _has_pending(channel):
                time.sleep(_DRAIN_GRACE_SECONDS)
                if not _has_pending(channel):
                    break
                continue

            if time.monotonic() > deadline:
                msg = (
                    f"{config.name}: command did not finish within "
                    f"{config.command_timeout_seconds}s on {config.target}"
                )
                raise SshCommandTimeoutError(msg)

            if not read_any:
                time.sleep(_POLL_SECONDS)

        exit_code = channel.recv_exit_status() if channel.exit_status_ready() else None
    except TimeoutError as exception:
        msg = f"{config.name}: timed out reading command output from {config.target}"
        raise SshCommandTimeoutError(msg) from exception
    finally:
        channel.close()

    if truncated:
        stdout = stdout[: config.max_output_bytes]
        stderr = stderr[: config.max_output_bytes]

    return _decode(stdout), _decode(stderr), exit_code, truncated


def _drain(channel, stdout: bytearray, stderr: bytearray) -> bool:
    read_any = False
    while channel.recv_ready():
        chunk = channel.recv(_READ_CHUNK)
        if not chunk:
            break
        stdout.extend(chunk)
        read_any = True
    while channel.recv_stderr_ready():
        chunk = channel.recv_stderr(_READ_CHUNK)
        if not chunk:
            break
        stderr.extend(chunk)
        read_any = True
    return read_any


def _has_pending(channel) -> bool:
    return channel.recv_ready() or channel.recv_stderr_ready()


def _decode(data: bytearray) -> str:
    """Decode terminal bytes, keeping going through whatever encoding the command used."""
    text = bytes(data).decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")
