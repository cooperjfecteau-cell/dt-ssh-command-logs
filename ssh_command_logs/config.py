"""Endpoint configuration: parsing and validation.

Monitoring configurations reach the extension as raw dicts shaped by
``extension/activationSchema.json``. The tenant validates against that schema, but the
extension also runs from ``dt-sdk run`` with a hand-written ``activation.json``, and a
schema can drift from the code that reads it. Everything is normalised and checked once
here so the SSH and log layers can trust their inputs, and so ``fastcheck`` can reject a
broken configuration before opening a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AUTH_PASSWORD = "password"
AUTH_KEY_FILE = "keyFile"
AUTH_KEY_CONTENT = "keyContent"
AUTH_TYPES = (AUTH_PASSWORD, AUTH_KEY_FILE, AUTH_KEY_CONTENT)

HOST_KEY_PINNED = "pinnedFingerprint"
HOST_KEY_KNOWN_HOSTS = "knownHosts"
HOST_KEY_ACCEPT_ANY = "acceptAny"
HOST_KEY_MODES = (HOST_KEY_PINNED, HOST_KEY_KNOWN_HOSTS, HOST_KEY_ACCEPT_ANY)

DEFAULTS = {
    "port": 22,
    "authType": AUTH_PASSWORD,
    "hostKeyVerification": HOST_KEY_PINNED,
    "usePty": False,
    "intervalMinutes": 5,
    "connectTimeoutSeconds": 15,
    "commandTimeoutSeconds": 60,
    "logSource": "ssh.command",
    "splitLines": True,
    "maxLines": 1000,
    "maxOutputBytes": 1024 * 1024,
}


class ConfigError(ValueError):
    """A monitoring configuration endpoint that cannot be run as written."""


@dataclass(frozen=True)
class EndpointConfig:
    """One command, on one host, on one schedule."""

    name: str
    host: str
    port: int
    username: str
    command: str
    auth_type: str = AUTH_PASSWORD
    password: str = ""
    private_key_path: str = ""
    private_key_content: str = ""
    private_key_passphrase: str = ""
    host_key_verification: str = HOST_KEY_PINNED
    host_key_fingerprint: str = ""
    known_hosts_path: str = ""
    use_pty: bool = False
    interval_minutes: int = 5
    connect_timeout_seconds: int = 15
    command_timeout_seconds: int = 60
    log_source: str = "ssh.command"
    split_lines: bool = True
    max_lines: int = 1000
    max_output_bytes: int = 1024 * 1024
    additional_attributes: dict[str, str] = field(default_factory=dict)

    @property
    def target(self) -> str:
        """Human-readable identity used in log messages and error text."""
        return f"{self.username}@{self.host}:{self.port}"

    @property
    def key(self) -> str:
        """Stable identity for scheduling state, so renaming a host starts a fresh clock."""
        return f"{self.name}|{self.target}"

    @classmethod
    def from_dict(cls, raw: dict, index: int = 0) -> EndpointConfig:
        """Build a validated config from one raw endpoint dict.

        Raises:
            ConfigError: if a required value is missing or out of range.
        """
        if not isinstance(raw, dict):
            msg = f"endpoint #{index + 1} is not an object"
            raise ConfigError(msg)

        label = _text(raw, "name") or f"endpoint-{index + 1}"

        def required(prop: str) -> str:
            value = _text(raw, prop)
            if not value:
                msg = f"{label}: '{prop}' is required"
                raise ConfigError(msg)
            return value

        auth_type = _choice(raw, "authType", AUTH_TYPES, label)
        host_key_verification = _choice(raw, "hostKeyVerification", HOST_KEY_MODES, label)

        config = cls(
            name=label,
            host=required("host"),
            port=_int(raw, "port", label, minimum=1, maximum=65535),
            username=required("username"),
            command=required("command"),
            auth_type=auth_type,
            password=_text(raw, "password"),
            private_key_path=_text(raw, "privateKeyPath"),
            private_key_content=_text(raw, "privateKeyContent", strip=False),
            private_key_passphrase=_text(raw, "privateKeyPassphrase", strip=False),
            host_key_verification=host_key_verification,
            host_key_fingerprint=_text(raw, "hostKeyFingerprint"),
            known_hosts_path=_text(raw, "knownHostsPath"),
            use_pty=_bool(raw, "usePty"),
            interval_minutes=_int(raw, "intervalMinutes", label, minimum=1, maximum=1440),
            connect_timeout_seconds=_int(raw, "connectTimeoutSeconds", label, minimum=1, maximum=300),
            command_timeout_seconds=_int(raw, "commandTimeoutSeconds", label, minimum=1, maximum=900),
            log_source=_text(raw, "logSource") or DEFAULTS["logSource"],
            split_lines=_bool(raw, "splitLines"),
            max_lines=_int(raw, "maxLines", label, minimum=1, maximum=50000),
            max_output_bytes=_int(raw, "maxOutputBytes", label, minimum=1024, maximum=10 * 1024 * 1024),
            additional_attributes=_attributes(raw.get("additionalAttributes"), label),
        )
        config._validate_auth()
        config._validate_host_key()
        return config

    def _validate_auth(self) -> None:
        if self.auth_type == AUTH_PASSWORD and not self.password:
            msg = f"{self.name}: password authentication selected but no password was set"
            raise ConfigError(msg)
        if self.auth_type == AUTH_KEY_FILE and not self.private_key_path:
            msg = f"{self.name}: key file authentication selected but no private key path was set"
            raise ConfigError(msg)
        if self.auth_type == AUTH_KEY_CONTENT and not self.private_key_content.strip():
            msg = f"{self.name}: pasted key authentication selected but no private key was set"
            raise ConfigError(msg)

    def _validate_host_key(self) -> None:
        # An empty pinned fingerprint is allowed through on purpose: SshCommandRunner turns
        # the first connection into an error that reports the fingerprint it actually saw,
        # which is the only convenient way to learn it without shell access to the ActiveGate.
        if self.host_key_verification == HOST_KEY_PINNED and self.host_key_fingerprint:
            fingerprint = self.host_key_fingerprint
            if not fingerprint.startswith("SHA256:"):
                msg = (
                    f"{self.name}: host key fingerprint must be the SHA256 form printed by "
                    f"ssh-keyscan, e.g. 'SHA256:abc...', got {fingerprint!r}"
                )
                raise ConfigError(msg)


def load_endpoints(activation_config) -> tuple[list[EndpointConfig], list[str]]:
    """Parse every endpoint, keeping the good ones and the reasons the others were dropped.

    A single mistyped endpoint must not stop the rest of the configuration from running,
    so failures are returned rather than raised.
    """
    raw_endpoints = []
    if activation_config is not None:
        try:
            raw_endpoints = activation_config.get("endpoints") or []
        except (AttributeError, TypeError):
            raw_endpoints = []

    configs: list[EndpointConfig] = []
    errors: list[str] = []
    for index, raw in enumerate(raw_endpoints):
        try:
            configs.append(EndpointConfig.from_dict(raw, index))
        except ConfigError as exception:
            errors.append(str(exception))
    return configs, errors


def _text(raw: dict, prop: str, *, strip: bool = True) -> str:
    value = raw.get(prop, DEFAULTS.get(prop, ""))
    if value is None:
        return ""
    value = str(value)
    return value.strip() if strip else value


def _bool(raw: dict, prop: str) -> bool:
    value = raw.get(prop, DEFAULTS.get(prop, False))
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _int(raw: dict, prop: str, label: str, *, minimum: int, maximum: int) -> int:
    value = raw.get(prop, DEFAULTS.get(prop))
    try:
        number = int(value)
    except (TypeError, ValueError):
        msg = f"{label}: '{prop}' must be a whole number, got {value!r}"
        raise ConfigError(msg) from None
    if not minimum <= number <= maximum:
        msg = f"{label}: '{prop}' must be between {minimum} and {maximum}, got {number}"
        raise ConfigError(msg)
    return number


def _choice(raw: dict, prop: str, allowed: tuple[str, ...], label: str) -> str:
    value = _text(raw, prop) or str(DEFAULTS.get(prop, ""))
    if value not in allowed:
        msg = f"{label}: '{prop}' must be one of {', '.join(allowed)}, got {value!r}"
        raise ConfigError(msg)
    return value


def _attributes(raw_list, label: str) -> dict[str, str]:
    if not raw_list:
        return {}
    if not isinstance(raw_list, list):
        msg = f"{label}: 'additionalAttributes' must be a list"
        raise ConfigError(msg)

    attributes: dict[str, str] = {}
    for entry in raw_list:
        if not isinstance(entry, dict):
            msg = f"{label}: every additional attribute must be an object with 'key' and 'value'"
            raise ConfigError(msg)
        key = str(entry.get("key", "")).strip()
        value = str(entry.get("value", "")).strip()
        if not key:
            msg = f"{label}: an additional attribute is missing its key"
            raise ConfigError(msg)
        attributes[key] = value
    return attributes
