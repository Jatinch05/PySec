import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format= "%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("tool.log"), # This is to save logs in files
        logging.StreamHandler()          # This prints to the console
    ]
)


def get_args():
    parser = argparse.ArgumentParser(
        description="Base CLI template for cybersecurity scripts"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single target host/IP")
    group.add_argument("--targets-file", help="Path to file with list of targets")

    parser.add_argument("--output", default="output.json", help="Output file path")
    parser.add_argument("--ports", default="1-1024", help="Port range or list, e.g. 22,80,443 or 1-1024")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use")

    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    logging.info(f"Arguments: {args}")

    if args.target:
        logging.info(f"Scanning single target: {args.target}")
    elif args.targets_file:
        logging.info(f"Reading targets from: {args.targets_file}")

    logging.info(f"Ports: {args.ports}, Threads: {args.threads}, Output: {args.output}")

