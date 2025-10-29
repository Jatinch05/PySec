import logging
import socket
import threading
import ipaddress
from cli import get_args
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format= "%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("scanner.log"), # This is to save logs in files
        logging.StreamHandler()          # This prints to the console
    ]
)



def parse_args(args):
    """
    Returns (ports, targets).
    Assumptions:
      - args.target or args.targets_file (one required).
      - targets_file contains one IPv4 address per non-empty line.
      - args.ports is comma-separated tokens like "22,80,443".
    """

    ports = []
    targets = []

    if args.target:
        targets.append(args.target.strip())

    elif args.targets_file:
        path = args.targets_file
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line_no, line in enumerate(f, start = 1):
                    ip = line.strip()
                    try:
                        valid_ip = ipaddress.ip_address(ip)
                        targets.append(valid_ip)
                    except ValueError:
                        logging.error(f"Invalid IP address found at line no {line_no}")
                        raise SystemExit(2)
                    
        else:
            logging.error("File doesn't exist at the given path")

    if args.ports:
        for token in args.ports.split(','):
            port = token.strip()
            try:
                int_port = int(port)
            except ValueError:
                logging.warning(f"Skipping non-integer port no  {port}")
                continue
            if 1 <= int_port <= 65535:
                ports.append(port)
            else:
                logging.warning(f"Skipping out of range port no {int_port}")
                continue
    
    if not ports:
        logging.info("No argument for port numbers found, continuing with defualt range 1 - 1024")
        ports.extend(list(range(1,1025)))
    
    ports = sorted(set(ports))

    return ports, targets 





if __name__ == "__main__":
    args = get_args()
    logging.info(f"Arguments {args}")
    ports, targets = parse_args(args)
    logging.info(f"Ports: {ports}, Targets: {targets}")


