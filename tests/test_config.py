"""Configuration parsing: defaults, validation, and partial-failure behaviour."""

from __future__ import annotations

import pytest

from ssh_command_logs.config import (
    AUTH_KEY_CONTENT,
    AUTH_KEY_FILE,
    HOST_KEY_PINNED,
    MAX_COMMANDS_PER_ENDPOINT,
    ConfigError,
    EndpointConfig,
    load_endpoints,
)


def raw(**overrides) -> dict:
    endpoint = {
        "name": "web-01",
        "host": "10.0.0.5",
        "username": "svc-dynatrace",
        "authType": "password",
        "password": "hunter2",
        "commands": [{"name": "disk", "command": "df -h /"}],
    }
    endpoint.update(overrides)
    return endpoint


class FakeActivationConfig:
    """Stands in for the SDK ActivationConfig, which proxies get() to the active context."""

    def __init__(self, endpoints):
        self._endpoints = endpoints

    def get(self, key, default=None):
        return {"endpoints": self._endpoints}.get(key, default)


class TestCommands:
    def test_several_commands_are_kept_in_order(self):
        config = EndpointConfig.from_dict(
            raw(
                commands=[
                    {"name": "uptime", "command": "uptime"},
                    {"name": "disk", "command": "df -h /"},
                    {"name": "failed", "command": "systemctl --failed --no-legend"},
                ]
            )
        )

        assert [command.name for command in config.commands] == ["uptime", "disk", "failed"]
        assert config.commands[2].command == "systemctl --failed --no-legend"

    def test_a_command_containing_commas_is_untouched(self):
        # Commands are a list of objects precisely so a delimiter cannot truncate this.
        command = "awk -F, '{print $2}' /etc/passwd | cut -d, -f1"
        config = EndpointConfig.from_dict(raw(commands=[{"name": "users", "command": command}]))

        assert config.commands[0].command == command

    def test_commands_inherit_the_endpoint_timeout_and_log_source(self):
        config = EndpointConfig.from_dict(
            raw(commandTimeoutSeconds=120, logSource="linux.checks")
        )

        assert config.commands[0].timeout_seconds == 120
        assert config.commands[0].log_source == "linux.checks"

    def test_a_command_can_override_the_timeout_and_log_source(self):
        config = EndpointConfig.from_dict(
            raw(
                commandTimeoutSeconds=30,
                logSource="linux.checks",
                commands=[
                    {"name": "quick", "command": "uptime"},
                    {
                        "name": "slow",
                        "command": "find / -name core",
                        "timeoutSeconds": 600,
                        "logSource": "linux.audit",
                    },
                ],
            )
        )

        assert config.commands[0].timeout_seconds == 30
        assert config.commands[0].log_source == "linux.checks"
        assert config.commands[1].timeout_seconds == 600
        assert config.commands[1].log_source == "linux.audit"

    def test_a_zero_timeout_means_use_the_endpoint_default(self):
        # The schema uses 0 rather than null for "unset", so it must not become a 0s timeout.
        config = EndpointConfig.from_dict(
            raw(commandTimeoutSeconds=45, commands=[{"name": "a", "command": "uptime", "timeoutSeconds": 0}])
        )

        assert config.commands[0].timeout_seconds == 45

    def test_an_endpoint_with_no_commands_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(commands=[]))

        assert "at least one command" in str(raised.value)

    def test_a_command_with_no_text_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(commands=[{"name": "empty", "command": "   "}]))

        assert "'command' is required" in str(raised.value)

    def test_duplicate_command_names_are_rejected(self):
        # Names become ssh.command_name; duplicates would make two commands' records
        # indistinguishable in a query.
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(
                raw(commands=[{"name": "check", "command": "a"}, {"name": "check", "command": "b"}])
            )

        assert "both named 'check'" in str(raised.value)

    def test_unnamed_commands_get_positional_names(self):
        config = EndpointConfig.from_dict(
            raw(commands=[{"command": "uptime"}, {"command": "df -h /"}])
        )

        assert [command.name for command in config.commands] == ["command-1", "command-2"]

    def test_too_many_commands_is_rejected(self):
        many = [{"name": f"c{index}", "command": "true"} for index in range(MAX_COMMANDS_PER_ENDPOINT + 1)]
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(commands=many))

        assert "at most" in str(raised.value)

    def test_a_single_command_field_is_still_accepted(self):
        # Keeps a configuration written against the earlier single-command schema working.
        endpoint = raw()
        del endpoint["commands"]
        endpoint["command"] = "df -h /"

        config = EndpointConfig.from_dict(endpoint)

        assert len(config.commands) == 1
        assert config.commands[0].command == "df -h /"
        assert config.commands[0].name == "web-01"


class TestEndpointDefaults:
    def test_defaults_are_applied(self):
        config = EndpointConfig.from_dict(raw())

        assert config.port == 22
        assert config.interval_minutes == 5
        assert config.log_source == "ssh.command"
        assert config.split_lines is True
        assert config.max_lines == 1000
        assert config.host_key_verification == HOST_KEY_PINNED
        assert config.use_pty is False
        assert config.target == "svc-dynatrace@10.0.0.5:22"

    def test_explicit_values_win(self):
        config = EndpointConfig.from_dict(
            raw(port=2202, intervalMinutes=15, logSource="nginx.status", splitLines=False, usePty=True)
        )

        assert config.port == 2202
        assert config.interval_minutes == 15
        assert config.log_source == "nginx.status"
        assert config.split_lines is False
        assert config.use_pty is True

    def test_additional_attributes_become_a_mapping(self):
        config = EndpointConfig.from_dict(
            raw(
                additionalAttributes=[
                    {"key": "environment", "value": "prod"},
                    {"key": "team", "value": "platform"},
                ]
            )
        )

        assert config.additional_attributes == {"environment": "prod", "team": "platform"}


class TestValidation:
    @pytest.mark.parametrize("missing", ["host", "username"])
    def test_required_fields_are_enforced(self, missing):
        endpoint = raw()
        endpoint[missing] = ""

        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(endpoint)

        assert missing in str(raised.value)

    def test_password_auth_without_a_password_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(password=""))

        assert "no password" in str(raised.value)

    def test_key_file_auth_without_a_path_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(authType=AUTH_KEY_FILE, privateKeyPath=""))

        assert "private key path" in str(raised.value)

    def test_pasted_key_auth_without_a_key_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(authType=AUTH_KEY_CONTENT, privateKeyContent="   "))

        assert "no private key" in str(raised.value)

    def test_out_of_range_port_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(port=70000))

        assert "between 1 and 65535" in str(raised.value)

    def test_non_numeric_interval_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(intervalMinutes="often"))

        assert "whole number" in str(raised.value)

    def test_unknown_auth_type_is_rejected(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(authType="kerberos"))

        assert "must be one of" in str(raised.value)

    def test_fingerprint_must_be_the_sha256_form(self):
        with pytest.raises(ConfigError) as raised:
            EndpointConfig.from_dict(raw(hostKeyVerification=HOST_KEY_PINNED, hostKeyFingerprint="ab:cd:ef"))

        assert "SHA256:" in str(raised.value)

    def test_empty_fingerprint_is_allowed_so_the_first_run_can_report_it(self):
        config = EndpointConfig.from_dict(raw(hostKeyVerification=HOST_KEY_PINNED, hostKeyFingerprint=""))

        assert config.host_key_fingerprint == ""


class TestLoadEndpoints:
    def test_one_broken_endpoint_does_not_drop_the_others(self):
        configs, errors = load_endpoints(
            FakeActivationConfig([raw(name="good"), raw(name="broken", host=""), raw(name="also-good")])
        )

        assert [config.name for config in configs] == ["good", "also-good"]
        assert len(errors) == 1
        assert "broken" in errors[0]

    def test_missing_endpoints_is_not_an_error(self):
        configs, errors = load_endpoints(FakeActivationConfig([]))

        assert configs == []
        assert errors == []

    def test_endpoint_key_distinguishes_same_name_on_different_hosts(self):
        first = EndpointConfig.from_dict(raw(name="disk", host="10.0.0.5"))
        second = EndpointConfig.from_dict(raw(name="disk", host="10.0.0.6"))

        assert first.key != second.key
