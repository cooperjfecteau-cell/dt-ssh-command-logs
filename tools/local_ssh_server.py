"""Run a throwaway SSH server on localhost so `dt-sdk run` has something to talk to.

    python tools/local_ssh_server.py            # listens on 127.0.0.1:2222

It answers with canned Linux output, so the whole extension loop — schedule, connect, run,
build log records — can be exercised without a Linux host or a Dynatrace tenant.
Development only: it accepts one hard-coded password and never runs anything.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.ssh_test_server import CommandSpec, SshTestServer  # noqa: E402

RESPONSES = {
    "uptime && df -h /": CommandSpec(
        stdout=(
            " 14:32:09 up 27 days,  3:14,  2 users,  load average: 0.42, 0.31, 0.28\n"
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   21G   27G  44% /"
        )
    ),
    "uptime": CommandSpec(stdout=" 14:32:09 up 27 days,  3:14,  2 users,  load average: 0.42, 0.31, 0.28"),
    "df -h /": CommandSpec(
        stdout="Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   21G   27G  44% /"
    ),
    "systemctl is-failed nginx": CommandSpec(stdout="active", exit_code=1),
    "cat /var/log/nonexistent": CommandSpec(
        stderr="cat: /var/log/nonexistent: No such file or directory", exit_code=1
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", default="demo")
    parser.add_argument("--password", default="demo-password")
    args = parser.parse_args()

    server = SshTestServer(RESPONSES, username=args.username, password=args.password, port=args.port)
    host, port = server.start()

    print(f"Fake SSH server listening on {host}:{port}")
    print(f"  user        {args.username}")
    print(f"  password    {args.password}")
    print(f"  fingerprint {server.fingerprint}")
    print(f"  commands    {', '.join(sorted(RESPONSES))}")
    print("Any other command is echoed back on stdout. Ctrl+C to stop.")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
