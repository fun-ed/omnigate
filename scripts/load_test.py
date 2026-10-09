#!/usr/bin/env python3
"""Closed-loop HTTP/1.1 load test. Standard library only; never reports capacity guarantees."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit


def percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def validate_target(raw, allow_remote):
    target = urlsplit(raw)
    if target.scheme not in ("http", "https") or not target.hostname:
        raise ValueError("target must be an HTTP(S) URL")
    if target.username is not None or target.password is not None or target.query or target.fragment:
        raise ValueError("credentials, query strings and fragments are not allowed in the target URL")
    try:
        local = ipaddress.ip_address(target.hostname).is_loopback
    except ValueError:
        local = target.hostname == "localhost"
    if not local and not allow_remote:
        raise ValueError("non-loopback load requires explicit --allow-remote and target-owner approval")
    if target.port is not None and not 1 <= target.port <= 65535:
        raise ValueError("invalid target port")
    return target


def sample_rss(pid):
    if pid is None:
        return None
    try:
        value = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)], text=True, timeout=2
        ).strip()
        return int(value) / 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def run_stage(target, concurrency, duration, timeout, pid, ssl_context):
    started = threading.Event()
    finished = threading.Event()
    deadline = [0.0]
    rss = []
    stage_start = time.monotonic()

    def start_stage():
        nonlocal stage_start
        stage_start = time.monotonic()
        deadline[0] = stage_start + duration
        started.set()

    ready = threading.Barrier(concurrency + 1, action=start_stage)

    def sample():
        started.wait()
        while not finished.is_set():
            value = sample_rss(pid)
            if value is not None:
                rss.append({"elapsed_s": round(time.monotonic() - stage_start, 3), "rss_mib": value})
            finished.wait(0.5)

    def worker():
        connection = None
        latencies = []
        statuses = Counter()
        errors = Counter()
        body_bytes = 0
        succeeded = 0
        ready.wait()
        while time.monotonic() < deadline[0] and not finished.is_set():
            started = time.perf_counter()
            try:
                if connection is None:
                    cls = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
                    kwargs = {"timeout": timeout}
                    if target.scheme == "https":
                        kwargs["context"] = ssl_context
                    connection = cls(target.hostname, target.port, **kwargs)
                connection.request("GET", target.path or "/")
                response = connection.getresponse()
                data = response.read((1 << 20) + 1)
                statuses[str(response.status)] += 1
                body_bytes += len(data)
                if len(data) > 1 << 20:
                    errors["body_limit"] += 1
                    connection.close()
                    connection = None
                elif response.status != 200:
                    errors["unexpected_status"] += 1
                else:
                    succeeded += 1
                    latencies.append((time.perf_counter() - started) * 1000)
            except (OSError, http.client.HTTPException):
                errors["request_error"] += 1
                if connection is not None:
                    connection.close()
                    connection = None
        if connection is not None:
            connection.close()
        return latencies, statuses, errors, body_bytes, succeeded

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    results = []
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            try:
                futures = [pool.submit(worker) for _ in range(concurrency)]
                ready.wait(timeout=30)
                results = [future.result() for future in futures]
            except BaseException:
                finished.set()
                started.set()
                ready.abort()
                raise
        elapsed = time.monotonic() - stage_start
    finally:
        finished.set()
        sampler.join(timeout=3)
    latencies, statuses, errors = [], Counter(), Counter()
    body_bytes = succeeded = 0
    for samples, counts, failures, size, success in results:
        latencies.extend(samples)
        statuses.update(counts)
        errors.update(failures)
        body_bytes += size
        succeeded += success
    total = succeeded + sum(errors.values())
    return {
        "concurrency": concurrency,
        "requested_duration_s": duration,
        "elapsed_s": elapsed,
        "completed": total,
        "successful": succeeded,
        "successful_requests_per_s": succeeded / elapsed,
        "error_count": sum(errors.values()),
        "error_rate": sum(errors.values()) / total if total else None,
        "errors": dict(errors),
        "statuses": dict(statuses),
        "response_body_bytes": body_bytes,
        "successful_latency_ms": {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
            "max": max(latencies) if latencies else None,
        },
        "server_sampled_rss_mib": {
            "min": min(x["rss_mib"] for x in rss) if rss else None,
            "max": max(x["rss_mib"] for x in rss) if rss else None,
            "last": rss[-1]["rss_mib"] if rss else None,
        },
        "rss_samples": rss,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/")
    parser.add_argument("--concurrency", default="1,10,40,100")
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--server-pid", type=int)
    parser.add_argument("--cafile", help="Optional CA file for HTTPS; verification is never disabled")
    parser.add_argument("--allow-remote", action="store_true", help="Use only after the target owner approves the load")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        target = validate_target(args.url, args.allow_remote)
        concurrency = [int(x) for x in args.concurrency.split(",")]
        if not concurrency or any(x < 1 or x > 256 for x in concurrency):
            raise ValueError("concurrency must be between 1 and 256")
        if not math.isfinite(args.duration) or not 0 < args.duration <= 3600:
            raise ValueError("duration must be between 0 and 3600 seconds")
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
            raise ValueError("timeout must be between 0 and 60 seconds")
        if args.server_pid is not None and args.server_pid <= 0:
            raise ValueError("server PID must be positive")
    except ValueError as error:
        parser.error(str(error))
    context = ssl.create_default_context(cafile=args.cafile) if target.scheme == "https" else None
    if args.server_pid is not None and sample_rss(args.server_pid) is None:
        parser.error("cannot sample the server PID with ps")
    output = Path(args.output)
    if output.exists():
        parser.error("output already exists; choose a new run filename")
    report = {
        "schema_version": 1,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"system": platform.system(), "machine": platform.machine(), "logical_cpus": os.cpu_count(), "python": sys.version.split()[0]},
        "target": args.url,
        "protocol": "HTTP/1.1",
        "model": "closed-loop; one keep-alive connection per worker; successful status is 200",
        "rss_scope": "server PID only; sampled every 0.5s; not total process-tree memory or a guaranteed peak",
        "limitations": ["No TLS or QUIC conclusions from HTTP-only runs", "Client may bottleneck, especially when client and server share a machine", "Not an open-loop capacity test or long-duration soak", "Latency percentiles include successful requests only", "Rate limiting/auth must be configured deliberately", "Responses larger than 1 MiB are rejected"],
        "idle_server_rss_mib": sample_rss(args.server_pid),
        "stages": [],
    }
    for amount in concurrency:
        row = run_stage(target, amount, args.duration, args.timeout, args.server_pid, context)
        report["stages"].append(row)
        print(f"c={amount}: {row['successful_requests_per_s']:.1f} successful req/s; errors={row['error_count']}; p99={row['successful_latency_ms']['p99']} ms", flush=True)
    report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        parser.error("output already exists; choose a new run filename")
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    return 1 if any(x["error_count"] or not x["successful"] for x in report["stages"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
