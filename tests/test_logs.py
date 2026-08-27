"""Log record construction: shape, severity, attributes and the limit behaviours."""

from __future__ import annotations

from datetime import datetime, timezone

from ssh_command_logs.config import EndpointConfig
from ssh_command_logs.logs import build_failure_event, build_log_events
from ssh_command_logs.ssh_client import CommandResult, SshAuthError

FIXED_TIME = datetime(2026, 8, 26, 14, 30, 15, 123456, tzinfo=timezone.utc)


def config(**overrides) -> EndpointConfig:
    values = {
        "name": "web-01 disk",
        "host": "10.0.0.5",
        "port": 22,
        "username": "svc-dynatrace",
        "command": "df -h /",
        "password": "hunter2",
        "log_source": "linux.disk",
    }
    values.update(overrides)
    return EndpointConfig(**values)


def result(**overrides) -> CommandResult:
    values = {
        "stdout": "Filesystem      Size  Used Avail Use%\n/dev/sda1        50G   21G   27G  44%",
        "stderr": "",
        "exit_code": 0,
        "duration_ms": 128.5,
        "started_at": FIXED_TIME,
    }
    values.update(overrides)
    return CommandResult(**values)


def test_one_record_per_output_line():
    events = build_log_events(config(), result())

    assert len(events) == 2
    assert events[0]["content"].startswith("Filesystem")
    assert events[1]["content"].startswith("/dev/sda1")
    assert [event["ssh.line"] for event in events] == [1, 2]


def test_records_carry_the_identifying_attributes():
    events = build_log_events(config(), result())
    event = events[0]

    assert event["log.source"] == "linux.disk"
    # host.name is what associates the record with the monitored Linux host rather than
    # with the ActiveGate that collected it.
    assert event["host.name"] == "10.0.0.5"
    assert event["ssh.endpoint"] == "web-01 disk"
    assert event["ssh.user"] == "svc-dynatrace"
    assert event["ssh.command"] == "df -h /"
    assert event["ssh.exit_code"] == 0
    assert event["ssh.stream"] == "stdout"
    assert event["severity"] == "INFO"


def test_timestamp_is_iso_utc_with_milliseconds():
    events = build_log_events(config(), result())

    assert events[0]["timestamp"] == "2026-08-26T14:30:15.123Z"


def test_additional_attributes_are_attached_to_every_record():
    events = build_log_events(config(additional_attributes={"environment": "prod"}), result())

    assert all(event["environment"] == "prod" for event in events)


def test_no_secret_is_ever_placed_on_a_record():
    events = build_log_events(config(password="hunter2"), result())

    assert all("hunter2" not in str(value) for event in events for value in event.values())


def test_stderr_alone_is_a_warning():
    events = build_log_events(config(), result(stderr="warning: reading past end", exit_code=0))
    stderr_events = [event for event in events if event["ssh.stream"] == "stderr"]

    assert stderr_events[0]["severity"] == "WARN"


def test_stderr_with_a_failed_exit_is_an_error():
    events = build_log_events(config(), result(stdout="", stderr="No such file", exit_code=2))

    assert events[0]["severity"] == "ERROR"
    assert events[0]["ssh.exit_code"] == 2


def test_empty_output_still_produces_a_record():
    events = build_log_events(config(), result(stdout="", stderr=""))

    assert len(events) == 1
    assert events[0]["ssh.empty_output"] is True
    assert "no output" in events[0]["content"]


def test_unsplit_output_is_one_multiline_record():
    events = build_log_events(config(split_lines=False), result())

    assert len(events) == 1
    assert "\n" in events[0]["content"]
    assert "ssh.line" not in events[0]


def test_line_cap_stops_ingest_and_says_so():
    payload = "\n".join(f"line-{index}" for index in range(200))
    events = build_log_events(config(max_lines=10), result(stdout=payload))

    line_events = [event for event in events if "ssh.line" in event]
    assert len(line_events) == 10
    assert "stopped after 10 lines" in events[-1]["content"]
    assert events[-1]["severity"] == "WARN"


def test_truncation_is_flagged_and_explained():
    events = build_log_events(config(max_output_bytes=4096), result(truncated=True))

    assert all(event["ssh.truncated"] is True for event in events)
    assert "Output truncated at 4096 bytes" in events[-1]["content"]


def test_blank_lines_are_dropped():
    events = build_log_events(config(), result(stdout="first\n\n   \nsecond\n"))

    assert [event["content"] for event in events] == ["first", "second"]


def test_failure_event_names_the_cause():
    event = build_failure_event(config(), SshAuthError("web-01 disk: authentication failed"))

    assert event["severity"] == "ERROR"
    assert event["ssh.error_type"] == "SshAuthError"
    assert event["ssh.failed"] is True
    assert "authentication failed" in event["content"]
    assert event["log.source"] == "linux.disk"
