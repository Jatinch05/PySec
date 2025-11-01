import argparse
import os
import logging
import ipaddress
from typing import List, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(prog="scanner", description="Simple threaded TCP port scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target",action="append", help="Single target IP or hostname")
    group.add_argument("--targets-file", help="Path to file containing one IP/hostname per line")
    parser.add_argument("--ports", help="Comma-separated ports (e.g. 22,80,443). Default: 1-1024", default=None)
    parser.add_argument("--threads", type=int, default=None, help="Number of worker threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout seconds (default: 3.0)")
    parser.add_argument("--output", type= Path, default=Path("data/outputs/scan_results.json"), help="Output JSON file")
    return parser.parse_args()

