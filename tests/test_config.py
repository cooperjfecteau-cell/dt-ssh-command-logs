"""Configuration parsing: defaults, validation, and partial-failure behaviour."""

from __future__ import annotations

import pytest

from ssh_command_logs.config import (
    AUTH_KEY_CONTENT,
    AUTH_KEY_FILE,
    HOST_KEY_PINNED,
    ConfigError,
    EndpointConfig,
    load_endpoints,
)


def raw(**overrides) -> dict:
    endpoint = {
        "name": "web-01 disk",
        "host": "10.0.0.5",
        "username": "svc-dynatrace",
        "authType": "password",
        "password": "hunter2",
        "command": "df -h /",
    }
    endpoint.update(overrides)
    return endpoint


class FakeActivationConfig:
    """Stands in for the SDK ActivationConfig, which proxies get() to the active context."""

    def __init__(self, endpoints):
        self._endpoints = endpoints

    def get(self, key, default=None):
        return {"endpoints": self._endpoints}.get(key, default)


def test_defaults_are_applied():
    config = EndpointConfig.from_dict(raw())

    assert config.port == 22
    assert config.interval_minutes == 5
    assert config.log_source == "ssh.command"
    assert config.split_lines is True
    assert config.max_lines == 1000
    assert config.host_key_verification == HOST_KEY_PINNED
    assert config.use_pty is False
    assert config.target == "svc-dynatrace@10.0.0.5:22"


def test_explicit_values_win():
    config = EndpointConfig.from_dict(
        raw(port=2202, intervalMinutes=15, logSource="nginx.status", splitLines=False, usePty=True)
    )

    assert config.port == 2202
    assert config.interval_minutes == 15
    assert config.log_source == "nginx.status"
    assert config.split_lines is False
    assert config.use_pty is True


def test_additional_attributes_become_a_mapping():
    config = EndpointConfig.from_dict(
        raw(
            additionalAttributes=[
                {"key": "environment", "value": "prod"},
                {"key": "team", "value": "platform"},
            ]
        )
    )

    assert config.additional_attributes == {"environment": "prod", "team": "platform"}


@pytest.mark.parametrize("missing", ["host", "username", "command"])
def test_required_fields_are_enforced(missing):
    endpoint = raw()
    endpoint[missing] = ""

    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(endpoint)

    assert missing in str(raised.value)


def test_password_auth_without_a_password_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(password=""))

    assert "no password" in str(raised.value)


def test_key_file_auth_without_a_path_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(authType=AUTH_KEY_FILE, privateKeyPath=""))

    assert "private key path" in str(raised.value)


def test_pasted_key_auth_without_a_key_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(authType=AUTH_KEY_CONTENT, privateKeyContent="   "))

    assert "no private key" in str(raised.value)


def test_out_of_range_port_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(port=70000))

    assert "between 1 and 65535" in str(raised.value)


def test_non_numeric_interval_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(intervalMinutes="often"))

    assert "whole number" in str(raised.value)


def test_unknown_auth_type_is_rejected():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(authType="kerberos"))

    assert "must be one of" in str(raised.value)


def test_fingerprint_must_be_the_sha256_form():
    with pytest.raises(ConfigError) as raised:
        EndpointConfig.from_dict(raw(hostKeyVerification=HOST_KEY_PINNED, hostKeyFingerprint="ab:cd:ef"))

    assert "SHA256:" in str(raised.value)


def test_empty_fingerprint_is_allowed_so_the_first_run_can_report_it():
    config = EndpointConfig.from_dict(raw(hostKeyVerification=HOST_KEY_PINNED, hostKeyFingerprint=""))

    assert config.host_key_fingerprint == ""


def test_one_broken_endpoint_does_not_drop_the_others():
    configs, errors = load_endpoints(
        FakeActivationConfig([raw(name="good"), raw(name="broken", host=""), raw(name="also-good")])
    )

    assert [config.name for config in configs] == ["good", "also-good"]
    assert len(errors) == 1
    assert "broken" in errors[0]


def test_missing_endpoints_is_not_an_error():
    configs, errors = load_endpoints(FakeActivationConfig([]))

    assert configs == []
    assert errors == []


def test_endpoint_key_distinguishes_same_name_on_different_hosts():
    first = EndpointConfig.from_dict(raw(name="disk", host="10.0.0.5"))
    second = EndpointConfig.from_dict(raw(name="disk", host="10.0.0.6"))

    assert first.key != second.key
