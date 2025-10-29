import argparse
import os
import logging
import ipaddress
from typing import List, Tuple

logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(prog="scanner", description="Simple threaded TCP port scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single target IP or hostname")
    group.add_argument("--targets-file", help="Path to file containing one IP/hostname per line")
    parser.add_argument("--ports", help="Comma-separated ports (e.g. 22,80,443). Default: 1-1024", default=None)
    parser.add_argument("--threads", type=int, default=None, help="Number of worker threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout seconds (default: 3.0)")
    parser.add_argument("--output", default="scan_results.json", help="Output JSON file")
    return parser.parse_args()

def parse_and_normalize(args) -> Tuple[List[int], List[str]]:
    """
    Returns (ports, targets).
    Assumptions for this prototype:
      - targets-file contains one IP/hostname per non-empty line
      - ports is comma-separated integers only (no ranges)
    """
    ports = []
    targets: List[str] = []

    # targets
    if getattr(args, "target", None):
        targets.append(args.target.strip())
    else:
        path = getattr(args, "targets_file", None)
        if not path or not os.path.exists(path):
            logger.error("Targets file not found: %s", path)
            raise SystemExit(2)
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                ip = line.strip()
                if not ip:
                    continue
                
                try:
                    # if it's IPv4/IPv6 this will validate; hostnames will raise ValueError and we'll accept them
                    ipaddress.ip_address(ip)
                    targets.append(ip)
                except ValueError:
                    # treat as hostname
                    if " " in ip:
                        logger.error("Invalid target at line %d: %r", lineno, ip)
                        raise SystemExit(2)
                    targets.append(ip)


    ports_arg = getattr(args, "ports", None)
    if ports_arg:
        for token in ports_arg.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                p = int(token)
            except ValueError:
                logger.warning("Skipping non-integer port token: %r", token)
                continue
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                logger.warning("Skipping out-of-range port: %d", p)
    else:

        ports = list(range(1, 1025))

    ports = sorted(set(ports))
    if not targets:
        logger.error("No targets after parsing")
        raise SystemExit(2)
    return ports, targets
