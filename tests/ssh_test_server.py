"""A real, in-process SSH server for the tests.

Mocking paramiko would only prove the mock behaves. This serves an actual SSH handshake,
authentication and exec request on a loopback port, so the runner is tested against the
protocol it will meet on a real host, with no container or external server involved.
"""

from __future__ import annotations

import contextlib
import io
import socket
import threading
import time
from dataclasses import dataclass, field

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_USERNAME = "demo"
DEFAULT_PASSWORD = "demo-password"


@dataclass
class CommandSpec:
    """What the fake server should do when it receives a particular command."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    delay_seconds: float = 0.0
    # Emitted without a trailing newline, to prove partial last lines survive.
    trailing_newline: bool = True


def generate_host_key() -> paramiko.PKey:
    """A fresh Ed25519 host key per server instance."""
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


@dataclass
class SshTestServer:
    responses: dict[str, CommandSpec] = field(default_factory=dict)
    username: str = DEFAULT_USERNAME
    password: str | None = DEFAULT_PASSWORD
    authorized_key: paramiko.PKey | None = None
    host: str = "127.0.0.1"
    port: int = 0

    def __post_init__(self):
        self.host_key = generate_host_key()
        self._socket: socket.socket | None = None
        self._transports: list[paramiko.Transport] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self.commands_received: list[str] = []
        # Counts full SSH connections, as distinct from the session channels opened on
        # them. The gap between the two is the whole point of running several commands
        # over one session.
        self.connection_count = 0

    def start(self) -> tuple[str, int]:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(8)
        self.port = self._socket.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="ssh-test-accept")
        self._thread.start()
        return self.host, self.port

    def stop(self) -> None:
        self._running = False
        for transport in self._transports:
            with contextlib.suppress(Exception):
                transport.close()
        self._transports.clear()
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None

    def __enter__(self) -> SshTestServer:
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    @property
    def fingerprint(self) -> str:
        from ssh_command_logs.ssh_client import fingerprint_of

        return fingerprint_of(self.host_key)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                connection, _ = self._socket.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve, args=(connection,), daemon=True, name="ssh-test-session"
            ).start()

    def _serve(self, connection: socket.socket) -> None:
        self.connection_count += 1
        transport = paramiko.Transport(connection)
        transport.add_server_key(self.host_key)
        self._transports.append(transport)
        handler = _ServerHandler(self)
        try:
            transport.start_server(server=handler)
        except (paramiko.SSHException, OSError):
            # A client that hangs up mid-handshake is a normal end to a test, not a failure.
            return
        # Channels are serviced from the exec request callback; this just keeps the
        # connection thread alive for the lifetime of the session.
        while transport.is_active() and self._running:
            time.sleep(0.05)


def _wait_until_client_saw_the_reply(channel, timeout: float = 0.3) -> None:
    """Hold until the exec request has been acknowledged to the client.

    paramiko's transport thread sends the "channel request ok" reply only after
    ``check_channel_exec_request`` returns, so a responder thread started inside that
    callback can win the race and write output first, which the client sees as a closed
    channel. A real sshd replies before it writes, so this is an artifact of the double
    rather than something the runner has to tolerate. The client answers by closing its
    stdin, which arrives here as EOF; the timeout only covers clients that keep it open.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if getattr(channel, "eof_received", False):
            return
        time.sleep(0.005)


class _ServerHandler(paramiko.ServerInterface):
    def __init__(self, server: SshTestServer):
        self._server = server

    def get_allowed_auths(self, username):  # noqa: ARG002
        auths = []
        if self._server.password is not None:
            auths.append("password")
        if self._server.authorized_key is not None:
            auths.append("publickey")
        return ",".join(auths) or "none"

    def check_auth_password(self, username, password):
        if username == self._server.username and password == self._server.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        authorized = self._server.authorized_key
        if authorized is not None and username == self._server.username and key == authorized:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):  # noqa: ARG002
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *_args, **_kwargs):
        return True

    def check_channel_exec_request(self, channel, command):
        text = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else str(command)
        self._server.commands_received.append(text)
        spec = self._server.responses.get(text, CommandSpec(stdout=text, exit_code=0))
        threading.Thread(
            target=self._respond, args=(channel, spec), daemon=True, name="ssh-test-exec"
        ).start()
        return True

    def _respond(self, channel, spec: CommandSpec) -> None:
        try:
            _wait_until_client_saw_the_reply(channel)
            if spec.delay_seconds:
                time.sleep(spec.delay_seconds)
            for text, send in ((spec.stdout, channel.sendall), (spec.stderr, channel.sendall_stderr)):
                if not text:
                    continue
                payload = text if text.endswith("\n") or not spec.trailing_newline else text + "\n"
                send(payload.encode("utf-8"))
            channel.send_exit_status(spec.exit_code)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                channel.close()
