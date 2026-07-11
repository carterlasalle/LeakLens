"""Dependency-free microbenchmark: `python benchmarks/benchmark_scan.py`."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from leaklens.engine import Scanner


def main() -> None:
    line = "const configuration = { enabled: true, retries: 3 };\n"
    payload = (
        line * 100_000 + 'password = "Q9!wE8@rT7#y"\n'
    )  # leaklens:allow -- synthetic benchmark fixture
    scanner = Scanner()
    started = time.perf_counter()
    result = scanner.scan_text(payload, path="benchmark.js")
    elapsed = time.perf_counter() - started
    mib = len(payload.encode()) / 1024 / 1024
    print(
        f"Scanned {mib:.2f} MiB in {elapsed:.3f}s ({mib / elapsed:.1f} MiB/s); findings={len(result.findings)}"
    )


if __name__ == "__main__":
    main()
