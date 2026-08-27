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
    CommandConfig,
    EndpointConfig,
)
from ssh_command_logs.ssh_client import (
    CommandResult,
    SshAuthError,
    SshHostKeyError,
    run_commands,
)
from tests.ssh_test_server import DEFAULT_PASSWORD, DEFAULT_USERNAME, CommandSpec, SshTestServer


def endpoint(server: SshTestServer, *commands: str, timeout: int = 10, **overrides) -> EndpointConfig:
    values = {
        "name": "test-endpoint",
        "host": server.host,
        "port": server.port,
        "username": DEFAULT_USERNAME,
        "commands": tuple(
            CommandConfig(
                name=f"cmd-{position + 1}",
                command=command,
                timeout_seconds=timeout,
                log_source="ssh.command",
            )
            for position, command in enumerate(commands)
        ),
        "password": DEFAULT_PASSWORD,
        "host_key_verification": HOST_KEY_ACCEPT_ANY,
        "connect_timeout_seconds": 10,
        "command_timeout_seconds": timeout,
    }
    values.update(overrides)
    return EndpointConfig(**values)


def run_one(config: EndpointConfig) -> CommandResult:
    """Most tests configure a single command; this keeps them readable."""
    results = run_commands(config)
    assert len(results) == 1
    return results[0]


class TestOneSessionManyCommands:
    """The reason commands are a list rather than one command per endpoint."""

    def test_several_commands_share_a_single_ssh_connection(self):
        responses = {
            "uptime": CommandSpec(stdout="up 3 days"),
            "df -h /": CommandSpec(stdout="/dev/sda1 44%"),
            "systemctl is-system-running": CommandSpec(stdout="running"),
        }
        with SshTestServer(responses) as server:
            results = run_commands(
                endpoint(server, "uptime", "df -h /", "systemctl is-system-running")
            )

            # Three commands, three channels, but one handshake and one authentication.
            assert len(results) == 3
            assert server.connection_count == 1
            assert server.commands_received == ["uptime", "df -h /", "systemctl is-system-running"]

        assert [result.stdout.strip() for result in results] == [
            "up 3 days",
            "/dev/sda1 44%",
            "running",
        ]

    def test_each_result_knows_which_command_produced_it(self):
        with SshTestServer({"a": CommandSpec(stdout="1"), "b": CommandSpec(stdout="2")}) as server:
            results = run_commands(endpoint(server, "a", "b"))

        assert [result.command.name for result in results] == ["cmd-1", "cmd-2"]
        assert [result.command.command for result in results] == ["a", "b"]

    def test_one_failing_command_does_not_cost_the_others_their_output(self):
        # A slow command must not take down the rest of the endpoint; it is recorded on
        # its own result and the session carries on.
        responses = {
            "fast-1": CommandSpec(stdout="ok-1"),
            "slow": CommandSpec(stdout="never", delay_seconds=5),
            "fast-2": CommandSpec(stdout="ok-2"),
        }
        with SshTestServer(responses) as server:
            results = run_commands(endpoint(server, "fast-1", "slow", "fast-2", timeout=1))

            assert server.connection_count == 1

        assert results[0].stdout.strip() == "ok-1"
        assert results[0].succeeded

        assert results[1].error, "the slow command should have recorded a timeout"
        assert results[1].error_type == "SshCommandTimeoutError"
        assert not results[1].succeeded

        assert results[2].stdout.strip() == "ok-2"
        assert results[2].succeeded

    def test_a_per_command_timeout_overrides_the_endpoint_default(self):
        with SshTestServer({"slow": CommandSpec(stdout="done", delay_seconds=3)}) as server:
            config = endpoint(server, "slow", timeout=30)
            patient = config.commands[0]
            impatient = CommandConfig(
                name=patient.name, command=patient.command, timeout_seconds=1,
                log_source=patient.log_source,
            )
            results = run_commands(
                endpoint(server, "slow", timeout=30, commands=(impatient,))
            )

        assert results[0].error_type == "SshCommandTimeoutError"
        assert "within 1s" in results[0].error


class TestSingleCommand:
    def test_captures_stdout_and_exit_code(self):
        responses = {"uptime": CommandSpec(stdout="up 3 days,  1 user,  load average: 0.10")}
        with SshTestServer(responses) as server:
            result = run_one(endpoint(server, "uptime"))

        assert result.exit_code == 0
        assert result.succeeded
        assert "load average" in result.stdout
        assert result.stderr == ""
        assert result.duration_ms > 0
        assert result.host_key_fingerprint.startswith("SHA256:")

    def test_captures_stderr_and_nonzero_exit(self):
        responses = {
            "systemctl status nope": CommandSpec(
                stdout="", stderr="Unit nope.service could not be found.", exit_code=4
            )
        }
        with SshTestServer(responses) as server:
            result = run_one(endpoint(server, "systemctl status nope"))

        assert result.exit_code == 4
        assert not result.succeeded
        assert "could not be found" in result.stderr

    def test_multiline_output_is_preserved_in_order(self):
        payload = "\n".join(f"line-{index}" for index in range(1, 51))
        with SshTestServer({"seq": CommandSpec(stdout=payload)}) as server:
            result = run_one(endpoint(server, "seq"))

        lines = [line for line in result.stdout.split("\n") if line]
        assert lines[0] == "line-1"
        assert lines[-1] == "line-50"
        assert len(lines) == 50

    def test_the_server_receives_the_command_verbatim(self):
        command = "sh -c 'echo $((2+2))' | tr -d '\\n'"
        with SshTestServer({}) as server:
            run_one(endpoint(server, command))

        assert server.commands_received == [command]

    def test_a_command_containing_commas_survives(self):
        # The reason commands are a list of objects and not a delimited string.
        command = "awk -F, '{print $2}' /etc/passwd | cut -d, -f1"
        with SshTestServer({}) as server:
            run_one(endpoint(server, command))

        assert server.commands_received == [command]

    def test_output_is_truncated_at_the_byte_limit(self):
        payload = "x" * 200_000
        with SshTestServer({"big": CommandSpec(stdout=payload)}) as server:
            result = run_one(endpoint(server, "big", max_output_bytes=4096))

        assert result.truncated
        assert len(result.stdout) <= 4096

    def test_slow_command_records_a_timeout(self):
        with SshTestServer({"sleep": CommandSpec(stdout="done", delay_seconds=5)}) as server:
            result = run_one(endpoint(server, "sleep", timeout=1))

        assert result.error_type == "SshCommandTimeoutError"
        assert "did not finish within 1s" in result.error

    def test_pty_is_allocated_when_requested(self):
        with SshTestServer({"top -bn1": CommandSpec(stdout="tasks: 1")}) as server:
            result = run_one(endpoint(server, "top -bn1", use_pty=True))

        assert "tasks: 1" in result.stdout


class TestConnectionFailures:
    """These abort the whole endpoint, so they raise rather than land on a result."""

    def test_wrong_password_is_reported_as_an_auth_failure(self):
        with SshTestServer({}) as server, pytest.raises(SshAuthError) as raised:
            run_commands(endpoint(server, "uptime", password="wrong"))

        assert "authentication failed" in str(raised.value)

    def test_matching_pinned_fingerprint_connects(self):
        with SshTestServer({"uptime": CommandSpec(stdout="ok")}) as server:
            result = run_one(
                endpoint(
                    server, "uptime",
                    host_key_verification=HOST_KEY_PINNED,
                    host_key_fingerprint=server.fingerprint,
                )
            )

        assert result.stdout.strip() == "ok"

    def test_mismatched_pinned_fingerprint_is_refused(self):
        with SshTestServer({}) as server:
            with pytest.raises(SshHostKeyError) as raised:
                run_commands(
                    endpoint(
                        server, "uptime",
                        host_key_verification=HOST_KEY_PINNED,
                        host_key_fingerprint="SHA256:" + "A" * 43,
                    )
                )

            message = str(raised.value)
            assert "host key mismatch" in message
            # The message must name the key that was actually offered, so the operator can act.
            assert server.fingerprint in message

    def test_empty_pin_reports_the_fingerprint_to_configure(self):
        with SshTestServer({}) as server:
            with pytest.raises(SshHostKeyError) as raised:
                run_commands(
                    endpoint(
                        server, "uptime",
                        host_key_verification=HOST_KEY_PINNED,
                        host_key_fingerprint="",
                    )
                )

            assert server.fingerprint in str(raised.value)

    def test_no_command_runs_when_the_connection_fails(self):
        with SshTestServer({}) as server:
            with pytest.raises(SshAuthError):
                run_commands(endpoint(server, "a", "b", "c", password="wrong"))

            assert server.commands_received == []


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
        result = run_one(
            endpoint(
                server, "whoami",
                password="",
                auth_type=AUTH_KEY_CONTENT,
                private_key_content=pem,
            )
        )

    assert result.stdout.strip() == "demo"
