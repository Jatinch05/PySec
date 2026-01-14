import logging
from pathlib import Path
import sys
from scapy.all import get_if_list
from typing import List
from .checker import has_privileges
from .reader import read_input


logger = logging.getLogger(__name__)


def setup_logging():
    """Configure logging for the sniffer module."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    Path("logs").mkdir(exist_ok=True)

    fh = logging.FileHandler(Path("logs/sniffer.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root.addHandler(ch)



def get_interfaces() -> List[str]:
    return get_if_list()


    
def main():
    setup_logging()
    if not has_privileges():
        logger.error("Administrator/root privileges are required")
        sys.exit(2)
    ifaces = get_interfaces()
    selected = read_input(ifaces)


    
if __name__ == "__main__":
    main()