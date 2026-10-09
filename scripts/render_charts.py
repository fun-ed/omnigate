#!/usr/bin/env python3
"""Render measured JSON/Go benchmark data as standalone accessible SVG images."""
import argparse
from html import escape
import json
from pathlib import Path
import re


COLORS = ["#2563eb", "#dc2626", "#059669", "#7c3aed"]
WIDTH, HEIGHT = 960, 540
LEFT, RIGHT, TOP, BOTTOM = 96, 920, 110, 425


def text(x, y, content, size=14, fill="#334155", anchor="start"):
    return f'<text x="{x:.2f}" y="{y:.2f}" font-size="{size}" fill="{fill}" text-anchor="{anchor}">{escape(str(content))}</text>'


def base(title, description):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img">',
            f'<title>{escape(title)}</title><desc>{escape(description)}</desc>',
            '<rect width="960" height="540" fill="#ffffff"/>',
            '<g font-family="Arial, Helvetica, sans-serif">',
            text(40, 43, title, 24, "#0f172a"), text(40, 72, description, 13)]


def line_chart(title, description, points, series, unit, baseline=None):
    if not points:
        raise ValueError("no measured stages")
    values = [v for _, data in series for v in data if v is not None]
    if baseline is not None:
        values.append(baseline)
    ymax = max(values + [0.001]) * 1.15
    xmax, xmin = max(points), min(points)
    x = lambda v: (LEFT + RIGHT) / 2 if xmax == xmin else LEFT + (v - xmin) / (xmax - xmin) * (RIGHT - LEFT)
    y = lambda v: BOTTOM - v / ymax * (BOTTOM - TOP)
    rows = base(title, description)
    for i in range(6):
        value = ymax * i / 5
        yy = y(value)
        rows.append(f'<line x1="{LEFT}" y1="{yy:.2f}" x2="{RIGHT}" y2="{yy:.2f}" stroke="#e2e8f0"/>')
        rows.append(text(LEFT - 12, yy + 5, f"{value:.2f}" if value < 100 else f"{value:.0f}", anchor="end"))
    rows.append(f'<path d="M {LEFT} {TOP} V {BOTTOM} H {RIGHT}" fill="none" stroke="#64748b"/>')
    rows.append(f'<g transform="translate(24 {(TOP + BOTTOM) / 2}) rotate(-90)">' + text(0, 0, unit, 12, anchor="middle") + '</g>')
    for point in points:
        rows.append(text(x(point), BOTTOM + 25, point, anchor="middle"))
    rows.append(text((LEFT + RIGHT) / 2, 478, "Concurrent HTTP/1.1 workers", 14, anchor="middle"))
    if baseline is not None:
        yy = y(baseline)
        rows.append(f'<line x1="{LEFT}" y1="{yy:.2f}" x2="{RIGHT}" y2="{yy:.2f}" stroke="#94a3b8" stroke-dasharray="6 5"/>')
        rows.append(text(RIGHT, yy - 6, f"Idle RSS: {baseline:.2f} MiB", 12, anchor="end"))
    for index, (name, data) in enumerate(series):
        color = COLORS[index % len(COLORS)]
        coords = [(x(point), y(value), value) for point, value in zip(points, data) if value is not None]
        if coords:
            path = "M " + " L ".join(f"{xx:.2f} {yy:.2f}" for xx, yy, _ in coords)
            rows.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.5"/>')
            for xx, yy, value in coords:
                rows.append(f'<circle cx="{xx:.2f}" cy="{yy:.2f}" r="5" fill="{color}"><title>{escape(name)}: {value:.3f} {escape(unit)}</title></circle>')
        rows.append(f'<rect x="{LEFT + index * 190}" y="88" width="12" height="12" fill="{color}"/>')
        rows.append(text(LEFT + index * 190 + 18, 99, name, 12))
    rows.append(text(40, 515, "Same-host closed-loop test. No cross-server comparison or capacity guarantee.", 12))
    return "\n".join(rows + ["</g></svg>\n"])


def benchmark_chart(raw):
    pattern = r"^(Benchmark\w+)-\d+\s+\d+\s+([0-9.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op"
    measurements = re.findall(pattern, raw, re.MULTILINE)
    if not measurements:
        raise ValueError("no Go benchmark measurements found")
    rows = base("Handler microbenchmarks", "No socket I/O, TLS, QUIC or client. ns/op is not network throughput.")
    max_ns = max(float(item[1]) for item in measurements) * 1.3
    start = 285
    for index, (name, ns, size, allocs) in enumerate(measurements):
        yy = 138 + index * 78
        label = name.removeprefix("Benchmark")
        length = float(ns) / max_ns * 580
        rows.append(text(40, yy + 20, label, 13))
        rows.append(f'<rect x="{start}" y="{yy}" width="{length:.2f}" height="28" rx="3" fill="{COLORS[index % len(COLORS)]}"/>')
        rows.append(text(start + length + 10, yy + 20, f"{ns} ns/op", 13))
        rows.append(text(start, yy + 48, f"{size} B/op; {allocs} allocs/op", 12))
    rows.append(text(40, 515, "Actual recorded Go output. Allocation bytes are not process RSS.", 12))
    return "\n".join(rows + ["</g></svg>\n"])


def render(report, bench=None):
    stages = report["stages"]
    points = [row["concurrency"] for row in stages]
    label = f"{report['protocol']}; {stages[0]['requested_duration_s']:g}s per stage; {report['environment']['system']} {report['environment']['machine']}"
    charts = {
        "http-throughput.svg": line_chart("Measured HTTP throughput", label, points,
            [("Successful requests/s", [row["successful_requests_per_s"] for row in stages])], "requests/s"),
        "http-latency.svg": line_chart("Successful request latency", label + "; failures excluded from percentiles", points,
            [(key, [row["successful_latency_ms"][key] for row in stages]) for key in ("p50", "p95", "p99")], "milliseconds"),
        "http-memory.svg": line_chart("Sampled server RSS, not guaranteed peak", label + "; excludes load generator and child processes", points,
            [("Sampled max RSS", [row["server_sampled_rss_mib"]["max"] for row in stages]),
             ("Last sampled RSS", [row["server_sampled_rss_mib"]["last"] for row in stages])], "MiB", report.get("idle_server_rss_mib")),
    }
    if bench is not None:
        charts["handler-benchmark.svg"] = benchmark_chart(bench)
    return charts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--bench", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--prefix", default="")
    args = parser.parse_args()
    if "/" in args.prefix or "\\" in args.prefix:
        parser.error("prefix must not contain a path separator")
    report = json.loads(args.input.read_text(encoding="utf-8"))
    charts = render(report, args.bench.read_text(encoding="utf-8") if args.bench else None)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    targets = {args.output_dir / (args.prefix + name): value for name, value in charts.items()}
    if any(path.exists() for path in targets):
        parser.error("a chart already exists; choose a new output directory or prefix")
    for path, value in targets.items():
        with path.open("x", encoding="utf-8") as stream:
            stream.write(value)
        print(path)


if __name__ == "__main__":
    main()
