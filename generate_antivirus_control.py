"""anti-virus trigger control script using eicar bytes"""

import os
import sys
import logging
from pathlib import Path

def create_eicar_file(path: str) -> None:
    """create an executable with eicar test bytes"""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    with open(path, "ab") as f:
        f.write(eicar_bytes)

def trigger_av_scan(path: str) -> None:
    """start the executable to ensure that the anti-visrus is triggered"""
    try:
        os.startfile(path)
    except OSError as exception:
        logging.warning("Could not prompt open: %s", exception)

def main():
    """main enry point"""
    eicar_file = f"{Path(__file__).parent.resolve()}\\trigger_av.exe"

    try:
        create_eicar_file(eicar_file)
        trigger_av_scan(eicar_file)     # force file to open to trigger AV scan.

    except OSError as exception:
        logging.error("Unexpected error: %s", exception)
        sys.exit(1)

if __name__ == "__main__":
    main()
