"""Extension entry point: schedule the endpoints, run their commands, ingest the output.

The SDK calls :meth:`ExtensionImpl.query` once a minute. Each endpoint carries its own
interval, so query decides which are due and runs those concurrently; a host that is slow
or unreachable must not hold up the others.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from dynatrace_extension import Extension, Status, StatusValue

from .config import EndpointConfig, load_endpoints
from .logs import build_failure_event, build_log_events
from .ssh_client import CommandResult, SshError, run_command

EXTENSION_NAME = "ssh_command_logs"

# Endpoints run in parallel, but an ActiveGate hosts many extensions; this keeps a large
# configuration from monopolising it.
MAX_CONCURRENT_ENDPOINTS = 8

# query() ticks every 60s. Without a tolerance an endpoint on a 5-minute interval would
# drift to 6 minutes whenever a tick lands a fraction of a second early.
INTERVAL_TOLERANCE_SECONDS = 5


class ExtensionImpl(Extension):
    def initialize(self):
        self._last_run: dict[str, float] = {}
        self._pool = ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_ENDPOINTS,
            thread_name_prefix="ssh-command",
        )

    def fastcheck(self) -> Status:
        """Refuse the monitoring configuration before any connection is attempted."""
        configs, errors = load_endpoints(self.activation_config)
        if errors:
            return Status(StatusValue.GENERIC_ERROR, "; ".join(errors))
        if not configs:
            return Status(StatusValue.GENERIC_ERROR, "No SSH command endpoints are configured")
        return Status(StatusValue.OK)

    def query(self):
        configs, errors = load_endpoints(self.activation_config)
        for error in errors:
            self.logger.error(f"Skipping endpoint: {error}")

        due = self._due_endpoints(configs)
        if not due:
            return

        self.logger.info(f"Running {len(due)} of {len(configs)} SSH endpoint(s)")

        futures = {self._pool.submit(run_command, config): config for config in due}
        for future in as_completed(futures):
            config = futures[future]
            try:
                self._ingest(config, future.result())
            except SshError as exception:
                self._ingest_failure(config, exception)
            except Exception as exception:  # noqa: BLE001 - one endpoint must not stop the rest
                self.logger.exception(f"{config.name}: unexpected failure")
                self._ingest_failure(config, exception)

    def on_shutdown(self):
        pool = getattr(self, "_pool", None)
        if pool is not None:
            pool.shutdown(wait=False)

    def _due_endpoints(self, configs: list[EndpointConfig]) -> list[EndpointConfig]:
        """Pick the endpoints whose interval has elapsed, and forget ones that were removed."""
        self._ensure_state()
        now = time.monotonic()
        live_keys = {config.key for config in configs}
        for stale in [key for key in self._last_run if key not in live_keys]:
            del self._last_run[stale]

        due = []
        for config in configs:
            last = self._last_run.get(config.key)
            interval = config.interval_minutes * 60 - INTERVAL_TOLERANCE_SECONDS
            if last is None or (now - last) >= interval:
                # Stamped before the run, not after, so a command that takes longer than its
                # interval does not immediately queue another one behind it.
                self._last_run[config.key] = now
                due.append(config)
        return due

    def _ingest(self, config: EndpointConfig, result: CommandResult) -> None:
        events = build_log_events(config, result)
        self.report_log_events(events)
        self._report_metrics(config, result, len(events))
        self.logger.info(
            f"{config.name}: exit={result.exit_code} lines={len(events)} "
            f"duration={result.duration_ms:.0f}ms"
        )

    def _ingest_failure(self, config: EndpointConfig, error: Exception) -> None:
        self.logger.error(f"{config.name}: {error}")
        self.report_log_event(build_failure_event(config, error))
        self.report_metric("ssh.command.success", 0, dimensions=_dimensions(config))

    def _report_metrics(self, config: EndpointConfig, result: CommandResult, line_count: int) -> None:
        dimensions = _dimensions(config)
        self.report_metric("ssh.command.duration", result.duration_ms, dimensions=dimensions)
        self.report_metric("ssh.command.output_lines", line_count, dimensions=dimensions)
        self.report_metric("ssh.command.success", 1 if result.succeeded else 0, dimensions=dimensions)
        if result.exit_code is not None:
            self.report_metric("ssh.command.exit_code", result.exit_code, dimensions=dimensions)

    def _ensure_state(self) -> None:
        # initialize() is the documented hook, but guarding here keeps query() safe if the
        # SDK ever schedules a callback before it has run.
        if not hasattr(self, "_last_run"):
            self.initialize()


def _dimensions(config: EndpointConfig) -> dict[str, str]:
    return {
        "endpoint": config.name,
        "host": config.host,
        "user": config.username,
    }


def main():
    ExtensionImpl(name=EXTENSION_NAME).run()


if __name__ == "__main__":
    main()
