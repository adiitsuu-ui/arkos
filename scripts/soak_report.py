#!/usr/bin/env python3
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/tmp/arkos-testnet")
LOGS = BASE / "logs"


def read_jsonl(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def iso(ts):
    if not ts:
        return "unknown"
    return datetime.fromtimestamp(int(ts), timezone.utc).isoformat()


def scan_logs():
    crashes = []
    db_errors = []
    reorgs = []
    rejects = []
    for path in sorted(LOGS.glob("node-*.log")):
        node = path.stem
        for line in path.read_text(errors="replace").splitlines():
            low = line.lower()
            if any(word in low for word in ("panic", "panicked", "segmentation fault", "unhandled")):
                crashes.append((node, line))
            if any(word in low for word in ("corrupt", "corruption", "deserialization failed")) or (
                any(word in low for word in ("rocksdb", "database")) and "failed" in low
            ):
                db_errors.append((node, line))
            if "reorg" in low:
                depth = re.search(r"depth[ =:]+(\d+)", line, re.I)
                if depth and int(depth.group(1)) > 0:
                    reorgs.append((node, line))
            if "reject" in low or "invalid" in low or "stale block" in low or "mismatch" in low:
                rejects.append((node, line))
    return crashes, db_errors, reorgs, rejects


def memory_stats(snapshots):
    out = {}
    for node in ("node-a", "node-b", "node-c"):
        values = [
            int(s["nodes"][node]["rss_kb"])
            for s in snapshots
            if node in s.get("nodes", {}) and s["nodes"][node].get("rss_kb") not in (None, "")
        ]
        out[node] = {
            "min_kb": min(values) if values else None,
            "max_kb": max(values) if values else None,
            "final_kb": values[-1] if values else None,
        }
    return out


def disk_stats(snapshots):
    values = [int(s["disk_kb"]) for s in snapshots if s.get("disk_kb") not in (None, "")]
    return {
        "min_kb": min(values) if values else None,
        "max_kb": max(values) if values else None,
        "final_kb": values[-1] if values else None,
    }


def snapshot_cadence(snapshots):
    gaps = []
    for before, after in zip(snapshots, snapshots[1:]):
        gaps.append(
            {
                "seconds": int(after["ts"]) - int(before["ts"]),
                "from": before["ts"],
                "to": after["ts"],
            }
        )
    max_gap = max((gap["seconds"] for gap in gaps), default=0)
    late = [gap for gap in gaps if gap["seconds"] > 35 * 60]
    return {"count": len(snapshots), "max_gap_seconds": max_gap, "late_gaps": late}


def node_topology_ok(snapshots):
    expected = {"node-a", "node-b", "node-c"}
    return bool(snapshots) and all(set(s.get("nodes", {}).keys()) == expected for s in snapshots)


def main():
    meta = {}
    meta_path = BASE / "run" / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())

    snapshots = read_jsonl(LOGS / "snapshots.log")
    events = read_jsonl(LOGS / "events.jsonl")
    mining = read_jsonl(LOGS / "mining.jsonl")
    crashes, db_errors, reorgs, rejects = scan_logs()

    final = snapshots[-1] if snapshots else {}
    final_nodes = final.get("nodes", {})
    heights = {n: v.get("height") for n, v in final_nodes.items()}
    tips = {n: v.get("tip") for n, v in final_nodes.items()}
    live = {n: v.get("running") for n, v in final_nodes.items()}
    height_agree = len(set(heights.values())) == 1 and len(heights) == 3 and all(v is not None for v in heights.values())
    tip_agree = len(set(tips.values())) == 1 and len(tips) == 3 and all(v not in (None, "") for v in tips.values())
    cadence = snapshot_cadence(snapshots)
    restart_counts = {
        node: sum(1 for e in events if e.get("type") == "restart" and e.get("node") == node)
        for node in ("node-a", "node-b", "node-c")
    }

    accepted_blocks = 0
    accepted_hashes = set()
    for row in mining:
        for result in row.get("results", []):
            inner = result.get("result", {})
            if result.get("ok") and inner.get("accepted"):
                accepted_blocks += 1
                if inner.get("blockHash"):
                    accepted_hashes.add(inner["blockHash"])

    start_ts = meta.get("start_ts")
    end_ts = meta.get("end_ts") or (snapshots[-1]["ts"] if snapshots else None)
    duration_seconds = int(end_ts or 0) - int(start_ts or 0) if start_ts and end_ts else 0

    restart_events = [e for e in events if e.get("type") == "restart"]
    partition_events = [e for e in events if e.get("type") == "partition"]
    unhandled_exit_events = [e for e in events if e.get("type") == "unexpected_exit"]
    rpc_not_ready_events = [e for e in events if e.get("type") == "rpc_not_ready"]

    criteria = [
        ("Duration >= 72 hours", duration_seconds >= 72 * 3600, f"{duration_seconds / 3600:.2f} hours"),
        ("3-node topology present in every snapshot", node_topology_ok(snapshots), f"{cadence['count']} snapshots"),
        ("3 nodes running at end", all(live.get(n) for n in ("node-a", "node-b", "node-c")), str(live)),
        ("Snapshots recorded at <=35 minute cadence", not cadence["late_gaps"], f"max_gap_seconds={cadence['max_gap_seconds']}, late_gaps={len(cadence['late_gaps'])}"),
        ("Mined blocks >= 500", len(accepted_hashes) >= 500 or max([v for v in heights.values() if isinstance(v, int)] or [0]) >= 500, f"{len(accepted_hashes)} accepted unique hashes observed"),
        ("3 intentional restarts per node", all(restart_counts[n] >= 3 for n in ("node-a", "node-b", "node-c")), str(restart_counts)),
        ("2 intentional partitions", len(partition_events) >= 2, f"{len(partition_events)} partition events"),
        ("1+ reorg events observed", len(reorgs) >= 1, f"{len(reorgs)} reorg log lines"),
        ("Unhandled crashes == 0", not crashes and not unhandled_exit_events, f"{len(crashes)} crash log lines, {len(unhandled_exit_events)} unexpected exits"),
        ("Database corruption == 0", not db_errors, f"{len(db_errors)} DB/corruption lines"),
        ("Final height agreement", height_agree and tip_agree, f"heights={heights}, tips={tips}"),
    ]
    overall = all(ok for _, ok, _ in criteria)

    lines = []
    lines.append("# Arkos 72-Hour Soak Test Report")
    lines.append("")
    lines.append(f"- Start time: {iso(start_ts)}")
    lines.append(f"- End time: {iso(end_ts)}")
    lines.append(f"- Duration: {duration_seconds / 3600:.2f} hours")
    lines.append(f"- Total blocks mined across all nodes: {accepted_blocks} accepted submissions")
    lines.append(f"- Unique block hashes observed by harness: {len(accepted_hashes)}")
    lines.append(f"- Snapshot count: {cadence['count']}")
    lines.append(f"- Snapshot max gap: {cadence['max_gap_seconds']} seconds")
    lines.append(f"- Restart counts: `{restart_counts}`")
    lines.append(f"- Final height agreement: {'yes' if height_agree and tip_agree else 'no'}")
    lines.append(f"- Final heights: `{heights}`")
    lines.append(f"- Final tips: `{tips}`")
    lines.append(f"- Overall verdict: {'PASS' if overall else 'FAIL'}")
    lines.append("")
    lines.append("## Criteria")
    for name, ok, detail in criteria:
        lines.append(f"- {'PASS' if ok else 'FAIL'}: {name} ({detail})")
    lines.append("")
    lines.append("## Restart Log")
    if restart_events:
        for e in restart_events:
            lines.append(f"- {iso(e.get('ts'))}: {e.get('node')} height_before={e.get('height_before')} height_after={e.get('height_after')} catch_up_seconds={e.get('catch_up_seconds')}")
    else:
        lines.append("- None recorded.")
    lines.append("")
    lines.append("## Partition Log")
    if partition_events:
        for e in partition_events:
            lines.append(f"- {iso(e.get('ts'))}: {e.get('name')} duration_seconds={e.get('duration_seconds')} divergence={e.get('divergence')} convergence_seconds={e.get('convergence_seconds')}")
    else:
        lines.append("- None recorded.")
    lines.append("")
    lines.append("## Reorg Events")
    if reorgs:
        for node, line in reorgs[:50]:
            depth = re.search(r"depth[ =:]+(\\d+)", line, re.I)
            lines.append(f"- {node}: depth={depth.group(1) if depth else 'unknown'} `{line[:240]}`")
    else:
        lines.append("- None found by case-insensitive `reorg` log scan.")
    lines.append("")
    lines.append("## Memory And Disk")
    lines.append(f"- Memory RSS by node: `{memory_stats(snapshots)}`")
    lines.append(f"- Disk usage /tmp/arkos-testnet: `{disk_stats(snapshots)}`")
    lines.append("")
    lines.append("## Snapshot Cadence")
    if cadence["late_gaps"]:
        for gap in cadence["late_gaps"][:50]:
            lines.append(f"- gap_seconds={gap['seconds']} from={iso(gap['from'])} to={iso(gap['to'])}")
    else:
        lines.append("- No gaps above 35 minutes.")
    lines.append("")
    lines.append("## Rejections")
    if rejects:
        for node, line in rejects[:50]:
            lines.append(f"- {node}: `{line[:240]}`")
    else:
        lines.append("- None found.")
    lines.append("")
    lines.append("## RPC Readiness Warnings")
    if rpc_not_ready_events:
        for e in rpc_not_ready_events[:50]:
            lines.append(f"- {iso(e.get('ts'))}: {e.get('node')} was not RPC-ready before the readiness wait limit.")
    else:
        lines.append("- None found.")
    lines.append("")
    lines.append("## Crashes Or Panics")
    if crashes or unhandled_exit_events:
        for node, line in crashes[:50]:
            lines.append(f"- {node}: `{line[:240]}`")
        for e in unhandled_exit_events[:50]:
            lines.append(f"- unexpected exit: `{e}`")
    else:
        lines.append("- None found.")
    lines.append("")
    lines.append("## Database Errors")
    if db_errors:
        for node, line in db_errors[:50]:
            lines.append(f"- {node}: `{line[:240]}`")
    else:
        lines.append("- None found.")

    (BASE / "SOAK_REPORT.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
