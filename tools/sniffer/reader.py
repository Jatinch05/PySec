import logging
import sys

logger = logging.getLogger(__name__)

def read_input(ifaces):
    selected = None
    while selected is None:
        print(ifaces)
        try:
            user_input = input("Select one of the above interfaces to sniff ").strip()
            if user_input not in ifaces:
                logger.error(f"The interface selected is not present in the system.")
            else:
                selected = user_input
        except KeyboardInterrupt:
            logger.info("Aborted by user")
            sys.exit(130)