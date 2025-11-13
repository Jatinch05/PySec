import socket
import threading
import queue
import logging
import errno
import time
from typing import List, Tuple, Dict

logger = logging.getLogger(__name__)

def map_target_port(ports: List[int], targets: List[str]) -> List[Tuple[str, int]]:
    out: List[Tuple[str,int]] = []
    for t in targets:
        for p in ports:
            out.append((t, p))
    return out

def _scan_one(host: str, port: int, timeout: float) -> Dict:
    """Perform a single TCP connect_ex scan + optional small banner read."""
    start = time.time()
    state = "error"
    svc = None
    banner = None
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((host, port))
        if rc == 0:
            state = "open"
            # try short banner grab
            try:
                s.settimeout(min(1.0, timeout))
                if port in (80, 8080):
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    except Exception: 
                        pass
                elif port == 21:
                    try:
                        s.sendall(b"\r\n")
                    except Exception:
                        pass
                data = b""
                try:
                    data = s.recv(256)
                except Exception:
                    data = b""
                if data:
                    try:
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        banner = repr(data[:64])
            except Exception:
                banner = None
            try:
                svc = socket.getservbyport(port)
            except Exception:
                svc = None
        else:
            name = errno.errorcode.get(rc)
            # Windows WSA codes mapping (common ones)
            if name in ("ECONNREFUSED",) or rc == 10061:
                state = "closed"
            elif name in ("ETIMEDOUT",) or rc == 10060:
                state = "filtered"
            elif name in ("EHOSTUNREACH", "ENETUNREACH") or rc in (10051, 10065):
                state = "unreachable"
            else:
                state = "error"
    except Exception as e:
        logger.debug("Exception scanning %s:%s -> %s", host, port, e)
        state = "error"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
        rtt = (time.time() - start) * 1000.0
        return {
            "host": host,
            "port": port,
            "state": state,
            "service": svc,
            "banner": banner,
            "rtt_ms": round(rtt, 2)
        }

def connect_target(ports: List[int], targets: List[str], workers: int = 20, timeout: float = 3.0) -> List[Dict]:
    """
    Populate queue, run threads, collect results. Thread-safe.
    Returns list of result dicts.
    """
    task_q = queue.Queue()
    results: List[Dict] = []
    results_lock = threading.Lock()

    items = map_target_port(ports, targets)
    for it in items:
        task_q.put(it)

    def worker_loop():
        while True:
            try:
                host, port = task_q.get(block=False)
            except queue.Empty:
                return
            try:
                rec = _scan_one(host, port, timeout)
                logger.debug("scan %s:%d -> %s", host, port, rec["state"])
                with results_lock:
                    results.append(rec)
            finally:
                task_q.task_done()

    worker_count = min(workers, len(items) or 1)
    threads = []
    for _ in range(worker_count):
        t = threading.Thread(target=worker_loop, daemon=True)
        t.start()
        threads.append(t)

    task_q.join()
    return results
