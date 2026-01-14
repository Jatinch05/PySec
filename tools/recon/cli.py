import argparse
import os
from pathlib import Path

def build_arg_parser():
    p = argparse.ArgumentParser(prog='recon', description="Command line tool for recon tool")
    g = p.add_mutually_exclusive_group(required= True)
    g.add_argument("--domain","-d", action="append", help="Target domain (repeatable). Example: -d example.com -d test.com")
    g.add_argument("--domains-file", "-D", type=Path,
                   help="File with one domain per line")
    # default_threads = min(256, os.cpu_count() * 10)
    no_of_cpus = os.cpu_count()
    if no_of_cpus:
        default_threads = min(256, no_of_cpus * 10)
    else:
        default_threads = 256
    p.add_argument("--wordlist", "-w", type=Path, default=Path("data/wordlists/subdomains-top1million-5000.txt"))
    p.add_argument("--max-wordlist", type=int, default=1000)
    p.add_argument("--threads", "-t", type=int, default=default_threads)
    p.add_argument("--http-timeout", type=float, default=3.0)
    p.add_argument("--dns-timeout", type=float, default=3.0)
    p.add_argument("--whois-timeout", type=float, default=8.0)
    p.add_argument("--rate", type=int, default=50)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--output", "-o", type=Path, default=Path("data/outputs/recon.json"))
    return p

def get_args():
    parser = build_arg_parser()
    args = parser.parse_args()
    if not args.domain and not args.domains_file:
        parser.error("either --domain or --domains-file is required")
    args.max_wordlist = max(1, int(getattr(args, "max_wordlist", 1000)))
    args.threads = max(1, int(getattr(args, "threads", 1)))
    return args




