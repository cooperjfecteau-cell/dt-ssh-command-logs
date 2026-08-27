"""End-to-end tests for the SSH runner against a real SSH server on loopback."""

from __future__ import annotations

import io

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ssh_command_logs.config import (
    AUTH_KEY_CONTENT,
    HOST_KEY_ACCEPT_ANY,
    HOST_KEY_PINNED,
    EndpointConfig,
)
from ssh_command_logs.ssh_client import (
    SshAuthError,
    SshCommandTimeoutError,
    SshHostKeyError,
    run_command,
)
from tests.ssh_test_server import DEFAULT_PASSWORD, DEFAULT_USERNAME, CommandSpec, SshTestServer


def endpoint(server: SshTestServer, command: str, **overrides) -> EndpointConfig:
    values = {
        "name": "test-endpoint",
        "host": server.host,
        "port": server.port,
        "username": DEFAULT_USERNAME,
        "command": command,
        "password": DEFAULT_PASSWORD,
        "host_key_verification": HOST_KEY_ACCEPT_ANY,
        "connect_timeout_seconds": 10,
        "command_timeout_seconds": 10,
    }
    values.update(overrides)
    return EndpointConfig(**values)


def test_captures_stdout_and_exit_code():
    responses = {"uptime": CommandSpec(stdout="up 3 days,  1 user,  load average: 0.10")}
    with SshTestServer(responses) as server:
        result = run_command(endpoint(server, "uptime"))

    assert result.exit_code == 0
    assert result.succeeded
    assert "load average" in result.stdout
    assert result.stderr == ""
    assert result.duration_ms > 0
    assert result.host_key_fingerprint.startswith("SHA256:")


def test_captures_stderr_and_nonzero_exit():
    responses = {
        "systemctl status nope": CommandSpec(
            stdout="",
            stderr="Unit nope.service could not be found.",
            exit_code=4,
        )
    }
    with SshTestServer(responses) as server:
        result = run_command(endpoint(server, "systemctl status nope"))

    assert result.exit_code == 4
    assert not result.succeeded
    assert "could not be found" in result.stderr


def test_multiline_output_is_preserved_in_order():
    payload = "\n".join(f"line-{index}" for index in range(1, 51))
    with SshTestServer({"seq": CommandSpec(stdout=payload)}) as server:
        result = run_command(endpoint(server, "seq"))

    lines = [line for line in result.stdout.split("\n") if line]
    assert lines[0] == "line-1"
    assert lines[-1] == "line-50"
    assert len(lines) == 50


def test_the_server_receives_the_command_verbatim():
    command = "sh -c 'echo $((2+2))' | tr -d '\\n'"
    with SshTestServer({}) as server:
        run_command(endpoint(server, command))

    assert server.commands_received == [command]


def test_output_is_truncated_at_the_byte_limit():
    payload = "x" * 200_000
    with SshTestServer({"big": CommandSpec(stdout=payload)}) as server:
        result = run_command(endpoint(server, "big", max_output_bytes=4096))

    assert result.truncated
    assert len(result.stdout) <= 4096


def test_slow_command_times_out():
    slow = {"sleep": CommandSpec(stdout="done", delay_seconds=5)}
    with SshTestServer(slow) as server, pytest.raises(SshCommandTimeoutError) as raised:
        run_command(endpoint(server, "sleep", command_timeout_seconds=1))

    assert "did not finish within 1s" in str(raised.value)


def test_wrong_password_is_reported_as_an_auth_failure():
    with SshTestServer({}) as server, pytest.raises(SshAuthError) as raised:
        run_command(endpoint(server, "uptime", password="wrong"))

    assert "authentication failed" in str(raised.value)


def test_pty_is_allocated_when_requested():
    with SshTestServer({"top -bn1": CommandSpec(stdout="tasks: 1")}) as server:
        result = run_command(endpoint(server, "top -bn1", use_pty=True))

    assert "tasks: 1" in result.stdout


class TestHostKeyVerification:
    def test_matching_pinned_fingerprint_connects(self):
        with SshTestServer({"uptime": CommandSpec(stdout="ok")}) as server:
            result = run_command(
                endpoint(
                    server,
                    "uptime",
                    host_key_verification=HOST_KEY_PINNED,
                    host_key_fingerprint=server.fingerprint,
                )
            )

        assert result.stdout.strip() == "ok"

    def test_mismatched_pinned_fingerprint_is_refused(self):
        with SshTestServer({}) as server, pytest.raises(SshHostKeyError) as raised:
            run_command(
                endpoint(
                    server,
                    "uptime",
                    host_key_verification=HOST_KEY_PINNED,
                    host_key_fingerprint="SHA256:" + "A" * 43,
                )
            )

        message = str(raised.value)
        assert "host key mismatch" in message
        # The message must name the key that was actually offered, so the operator can act.
        assert server.fingerprint in message

    def test_empty_pin_reports_the_fingerprint_to_configure(self):
        with SshTestServer({}) as server, pytest.raises(SshHostKeyError) as raised:
            run_command(
                endpoint(
                    server,
                    "uptime",
                    host_key_verification=HOST_KEY_PINNED,
                    host_key_fingerprint="",
                )
            )

        assert server.fingerprint in str(raised.value)


def test_private_key_authentication():
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))

    server = SshTestServer({"whoami": CommandSpec(stdout="demo")}, password=None, authorized_key=key)
    with server:
        result = run_command(
            endpoint(
                server,
                "whoami",
                password="",
                auth_type=AUTH_KEY_CONTENT,
                private_key_content=pem,
            )
        )

    assert result.stdout.strip() == "demo"
