import os
import ctypes

def has_privileges() -> bool:
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0