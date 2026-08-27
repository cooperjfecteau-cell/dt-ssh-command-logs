"""Turning command output into Dynatrace log records.

Payloads follow the generic log ingest shape: ``content``, ``timestamp``, ``severity`` and
any number of custom attributes. The SDK batches these and hands them to the EEC, which
forwards them to the tenant's log ingest endpoint.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .config import CommandConfig, EndpointConfig
from .ssh_client import CommandResult

SEVERITY_INFO = "INFO"
SEVERITY_WARN = "WARN"
SEVERITY_ERROR = "ERROR"

STREAM_STDOUT = "stdout"
STREAM_STDERR = "stderr"


def base_attributes(config: EndpointConfig, command: CommandConfig | None = None) -> dict:
    """Attributes every record from an endpoint carries, whether it succeeded or not.

    ``command`` is absent only for a connection-level failure, where no single command is
    to blame.
    """
    attributes = {
        "log.source": command.log_source if command is not None else config.log_source,
        # host.name is what Dynatrace uses to associate a log record with a monitored host,
        # so the records land on the target server rather than on the ActiveGate.
        "host.name": config.host,
        "ssh.endpoint": config.name,
        "ssh.host": config.host,
        "ssh.port": config.port,
        "ssh.user": config.username,
    }
    if command is not None:
        # The name is what you filter on when an endpoint runs several commands; the text
        # is there so a record explains itself without opening the configuration.
        attributes["ssh.command_name"] = command.name
        attributes["ssh.command"] = command.command
    attributes.update(config.additional_attributes)
    return attributes


def build_log_events(config: EndpointConfig, result: CommandResult) -> list[dict]:
    """Build the log records for one completed run.

    A run with no output still produces one record: an endpoint that silently stops
    returning anything is exactly the case someone needs to see in the log stream.
    """
    timestamp = _iso(result.started_at)
    common = base_attributes(config, result.command)
    common.update(
        {
            "ssh.exit_code": result.exit_code,
            "ssh.duration_ms": round(result.duration_ms, 3),
        }
    )
    if result.truncated:
        common["ssh.truncated"] = True

    # A command that failed once the session was already up reports its own error. The
    # other commands sharing that session are unaffected and still report their output.
    if result.error:
        return [
            {
                **common,
                "timestamp": timestamp,
                "severity": SEVERITY_ERROR,
                "content": f"SSH command failed: {result.error}",
                "ssh.stream": STREAM_STDERR,
                "ssh.error_type": result.error_type,
                "ssh.failed": True,
            }
        ]

    failed = not result.succeeded
    events: list[dict] = []

    if config.split_lines:
        events.extend(_line_events(result, common, timestamp, failed, config.max_lines))
    else:
        events.extend(_block_events(result, common, timestamp, failed))

    if not events:
        events.append(
            {
                **common,
                "timestamp": timestamp,
                "severity": SEVERITY_ERROR if failed else SEVERITY_INFO,
                "content": (
                    f"Command produced no output on {config.target} "
                    f"(exit code {result.exit_code})"
                ),
                "ssh.stream": STREAM_STDOUT,
                "ssh.empty_output": True,
            }
        )

    if result.truncated:
        events.append(
            {
                **common,
                "timestamp": timestamp,
                "severity": SEVERITY_WARN,
                "content": (
                    f"Output truncated at {config.max_output_bytes} bytes on {config.target}. "
                    f"Narrow the command or raise the limit to capture the rest."
                ),
                "ssh.stream": STREAM_STDOUT,
            }
        )

    return events


def build_failure_event(
    config: EndpointConfig, error: Exception, command: CommandConfig | None = None
) -> dict:
    """A record for a run that never got as far as producing output."""
    return {
        **base_attributes(config, command),
        "timestamp": _iso(datetime.now(timezone.utc)),
        "severity": SEVERITY_ERROR,
        "content": f"SSH command failed: {error}",
        "ssh.stream": STREAM_STDERR,
        "ssh.error_type": type(error).__name__,
        "ssh.failed": True,
    }


def _line_events(
    result: CommandResult,
    common: dict,
    timestamp: str,
    failed: bool,
    max_lines: int,
) -> list[dict]:
    events: list[dict] = []
    line_number = 0

    for stream, text in ((STREAM_STDOUT, result.stdout), (STREAM_STDERR, result.stderr)):
        for line in _lines(text):
            if line_number >= max_lines:
                events.append(
                    {
                        **common,
                        "timestamp": timestamp,
                        "severity": SEVERITY_WARN,
                        "content": f"Output stopped after {max_lines} lines",
                        "ssh.stream": stream,
                    }
                )
                return events
            line_number += 1
            events.append(
                {
                    **common,
                    "timestamp": timestamp,
                    "severity": _severity(stream, failed),
                    "content": line,
                    "ssh.stream": stream,
                    # Every line of one run shares the capture timestamp, so this is what
                    # restores the original order in a query.
                    "ssh.line": line_number,
                }
            )
    return events


def _block_events(result: CommandResult, common: dict, timestamp: str, failed: bool) -> list[dict]:
    events: list[dict] = []
    for stream, text in ((STREAM_STDOUT, result.stdout), (STREAM_STDERR, result.stderr)):
        if not text.strip():
            continue
        events.append(
            {
                **common,
                "timestamp": timestamp,
                "severity": _severity(stream, failed),
                "content": text.rstrip("\n"),
                "ssh.stream": stream,
            }
        )
    return events


def _severity(stream: str, failed: bool) -> str:
    if stream == STREAM_STDOUT:
        return SEVERITY_INFO
    # Plenty of well-behaved commands write progress to stderr, so stderr alone is only a
    # warning. It is promoted to an error when the command also exited non-zero.
    return SEVERITY_ERROR if failed else SEVERITY_WARN


def _lines(text: str) -> list[str]:
    if not text:
        return []
    return [line for line in text.split("\n") if line.strip()]


def _iso(moment: datetime) -> str:
    """Log ingest accepts ISO-8601; keep it UTC with milliseconds."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
