import logging
import sys
import json
import time
import os
import re
import ipaddress
from pathlib import Path
from itertools import islice
from tools.recon.cli import get_args
from tools.recon.workers import run_recon_tasks 


root = logging.getLogger()
root.setLevel(logging.DEBUG)
root.handlers.clear()

Path("logs").mkdir(exist_ok=True)

fh = logging.FileHandler(Path("logs/recon.log"), encoding="utf-8")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
root.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
root.addHandler(ch)

logger = logging.getLogger(__name__)


DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"


def _get_domains(args):
    domains_read = []

    if getattr(args, "domain", None):
        for domain_str in args.domain:
            domains_read.append((domain_str.strip(), 0))

    elif getattr(args, "domains_file", None):
        path = args.domains_file
        if not path or not path.exists():
            logger.error(f"Domains file not found: {path}")
            sys.exit(2)

        with open(path, "r", encoding='utf-8') as fh:
            for lineno, line in enumerate(fh, start=1):
                domain = line.strip()
                if domain:
                    domains_read.append((domain, lineno))

    domains_validated = []
    for domain, lineno in domains_read:
        try:
            ipaddress.ip_address(domain)
            domains_validated.append(domain)
        except ValueError:
            if re.match(DOMAIN_REGEX, domain):
                domains_validated.append(domain)
            else:
                if lineno > 0:
                    logger.warning(f"Invalid target at line {lineno}: {domain!r}. Skipping.")
                else:
                    logger.warning(f"Invalid target from --domain arg: {domain!r}. Skipping.")

    return sorted(list(set(domains_validated)))


def _load_wordlist(args):
    wordlist = []
    path: Path | None = getattr(args, "wordlist", None)
    limit = getattr(args, "max_wordlist", 1000)

    if path and path.exists():
        try:
            with open(path, "r", encoding='utf-8') as f:
                for line in islice(f, limit):
                    w = line.strip()
                    if w:
                        wordlist.append(w)
        except Exception as e:
            logger.error(f"Could not read wordlist {path}: {e}")
    elif path:
        logger.warning(f"Wordlist file not found: {path}")

    return wordlist


def choose_worker_count(args, total_tasks):
    user_requested = getattr(args, "threads", None)

    cpu = os.cpu_count() or 1
    IO_MULTIPLIER = 10
    MIN_WORKERS = 4
    MAX_WORKERS = 200

    auto_workers = max(MIN_WORKERS, cpu * IO_MULTIPLIER)
    workers = user_requested if (user_requested and user_requested > 0) else auto_workers
    workers = min(workers, total_tasks, MAX_WORKERS)
    return workers

def print_recon_summary_pretty(results: list):
    print("\nRECON SUMMARY\n")

    for rec in results:
        print(f"Target: {rec['domain']}")
        print(f"State : {rec['state']}")

        if rec.get("subdomains"):
            print(f"Found {len(rec['subdomains'])} subdomains:")
            for sub in rec["subdomains"][:10]:
                print(f"  - {sub['fqdn']}  ->  {', '.join(sub['ips'])}")
            if len(rec["subdomains"]) > 10:
                print(f"  ... ({len(rec['subdomains']) - 10} more)")

        if rec.get("http_probes"):
            print(f"HTTP Probes: {len(rec['http_probes'])}")
        print()

    print("\nEND\n")


def main():
    args = get_args()
    domains = _get_domains(args)
    wordlist = _load_wordlist(args)

    if not domains:
        logger.error("No valid domains or IPs to scan. Exiting.")
        sys.exit(1)

    total_tasks = len(domains)
    workers = choose_worker_count(args, total_tasks)

    logger.info(f"Starting recon: {total_tasks} target(s) (workers={workers}, wordlist_size={len(wordlist)})")

    start = time.perf_counter() # type: ignore

    results = run_recon_tasks(domains, wordlist, workers=workers, args=args)

    elapsed = time.perf_counter() - start # type: ignore
    logger.info("Recon complete: %d targets scanned in %.2fs", len(results), elapsed)

    out_path = Path(args.output)
    tmp = out_path.with_suffix(".tmp")

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        tmp.replace(out_path)
        logger.info(f"Results written to {out_path}")

    except Exception as e:
        logger.error(f"Failed to write results to {out_path}: {e}")

    if results:
        results.sort(key=lambda x: x["domain"])
        print_recon_summary_pretty(results)
    else:
        print("\nNo results found.\n")


if __name__ == "__main__":
    main()
