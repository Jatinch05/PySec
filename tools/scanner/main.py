import logging
import sys
import json
import time
import os
from pathlib import Path

from tools import cli
from tools.scanner.workers import connect_target

root = logging.getLogger()
root.setLevel(logging.DEBUG)
root.handlers.clear()

fh = logging.FileHandler("scanner.log", encoding="utf-8")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
root.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
root.addHandler(ch)

logger = logging.getLogger(__name__)

def print_table(results):

    rows = [("HOST", "PORT", "STATE", "SERVICE")]
    for r in results:
        rows.append((r["host"], str(r["port"]), r["state"], str(r.get("service") or "")))

    col_widths = [max(len(row[i]) for row in rows) for i in range(4)]
    fmt = "  ".join("{:<" + str(w) + "}" for w in col_widths)
    for row in rows:
        print(fmt.format(*row))

def choose_worker_count(args, targets, ports):
    """
    Auto-select worker count:
    - Uses cpu_count * IO_MULTIPLIER as baseline
    - Respects user override if provided and >0
    - Clamps to [MIN_WORKERS, MAX_WORKERS, total_tasks]
    """
    total_tasks = max(1, len(targets) * len(ports))
    user_requested = getattr(args, "threads", None)

    cpu = os.cpu_count() or 1
    IO_MULTIPLIER = 10         
    MIN_WORKERS = 4
    MAX_WORKERS = 200

    auto_workers = max(MIN_WORKERS, cpu * IO_MULTIPLIER)
    workers = user_requested if (user_requested and user_requested > 0) else auto_workers
    workers = min(workers, total_tasks, MAX_WORKERS)
    return workers

def main():
    args = cli.get_args()
    ports, targets = cli.parse_and_normalize(args)

    workers = choose_worker_count(args, targets, ports)
    logger.info("Starting scan: %d target(s) x %d port(s) = %d tasks (workers=%d, timeout=%.2fs)",
                len(targets), len(ports), len(targets)*len(ports), workers, args.timeout)

    start = time.perf_counter()
    results = connect_target(ports, targets, workers=workers, timeout=args.timeout)
    elapsed = time.perf_counter() - start

    
    unique_map = {}
    for r in results:
        key = (r["host"], r["port"])
        existing = unique_map.get(key)
        if existing is None or (r.get("rtt_ms") or 0) < (existing.get("rtt_ms") or 0):
            unique_map[key] = r
    unique_results = list(unique_map.values())

    open_count = sum(1 for r in unique_results if r["state"] == "open")
    logger.info("Scan complete: %d open / %d scanned in %.2fs", open_count, len(unique_results), elapsed)

    
    out_path = Path(args.output)
    tmp = out_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(unique_results, fh, indent=2)
    tmp.replace(out_path)  
    logger.info("Results written to %s", out_path)

    
    open_results = [r for r in unique_results if r["state"] == "open"]
    if open_results:
        open_results.sort(key=lambda x: (x["host"], x["port"]))
        print()
        print("Open ports:")
        print_table(open_results)
    else:
        print()
        print("No open ports found (or host filtered).")

if __name__ == "__main__":
    main()
