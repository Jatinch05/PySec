import queue
import threading
import logging
import ipaddress
from typing import List, Dict, Any, Optional
import whois
import dns.resolver
import httpx
from multiprocessing import Process, Queue as MPQueue
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def _whois_target(q: MPQueue, d: str) -> None:
    """Top-level worker used by Process to perform whois and send result via queue."""
    try:
        res = whois.whois(d)
        if hasattr(res, "dict"):
            q.put(dict(res.dict()))
        elif isinstance(res, dict):
            q.put(dict(res))
        else:
            q.put(dict(getattr(res, "__dict__", {}) or {}))
    except Exception:
        q.put(None)


def _get_whois(target: str, timeout: float) -> Optional[Dict]:
    """
    Performs a WHOIS lookup for a single domain or IP.
    Runs the lookup in a separate process and returns the dict or None on timeout/error.
    """
    q: MPQueue = MPQueue(1)
    p = Process(target=_whois_target, args=(q, target))
    p.start()
    p.join(timeout)
    if p.is_alive():
        try:
            p.terminate()
        except Exception:
            pass
        p.join()
        return None

    try:
        if not q.empty():
            return q.get_nowait()
    except Exception:
        pass
    return None


def _resolve_one(fqdn: str, timeout: float, nameservers=None) -> Optional[List[str]]:
    """Resolve a single fqdn -> list of IPs or None."""
    try:
        resolver = dns.resolver.Resolver()
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answers = resolver.resolve(fqdn, "A")
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception as e:
        logger.debug("DNS lookup error for %s: %s", fqdn, e)
        return None


def _enumerate_subdomains(domain: str, wordlist: List[str], timeout: float, max_workers: int = 50, nameservers=None) -> List[Dict]:
    """
    Concurrent DNS lookups for all words in the wordlist against a domain.
    Returns list of dicts: {"fqdn": ..., "ips": [...], "state": "found"}
    """
    results: List[Dict] = []
    if not wordlist:
        return results

    if nameservers is None:
        nameservers = ["8.8.8.8", "1.1.1.1"]

    workers = min(max_workers, max(4, len(wordlist)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for word in wordlist:
            fqdn = f"{word}.{domain}"
            futures[ex.submit(_resolve_one, fqdn, timeout, nameservers)] = fqdn

        for fut in as_completed(futures):
            fqdn = futures[fut]
            try:
                ips = fut.result()
                if ips:
                    results.append({"fqdn": fqdn, "ips": ips, "state": "found"})
            except Exception as e:
                logger.debug("Error resolving %s: %s", fqdn, e)
    return results


def _probe_http(fqdn_or_ip: str, timeout: float, retries: int) -> Dict:
    """
    Probes a single FQDN or IP for HTTP/HTTPS. Returns dict with url, status_code, final_url, state.
    """
    urls = [f"http://{fqdn_or_ip}", f"https://{fqdn_or_ip}"]
    with httpx.Client(timeout=timeout) as session:
        for url in urls:
            for attempt in range(retries):
                try:
                    response = session.get(url)
                    return {
                        "url": url,
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                        "state": "up"
                    }
                except httpx.RequestError as e:
                    logger.debug("HTTP request error for %s (attempt %d): %s", url, attempt + 1, e)
    return {"url": None, "status_code": None, "final_url": None, "state": "down"}


def _recon_one(target: str, wordlist: List[str], args: Any) -> Dict:
    """
    Orchestrates all recon tasks for a single target.
    Returns a dict that includes both 'target' and 'domain' keys (main.py expects 'domain').
    """
    logger.info("Recon for target: %s", target)
    record: Dict = {"target": target, "domain": target, "state": "unknown"}

    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    logger.info("Getting whois for: %s", target)
    whois_info = _get_whois(target, getattr(args, "whois_timeout", 8.0))
    record["whois"] = whois_info

    if is_ip:
        record["state"] = "ip"
        return record

    logger.info("Enumerating subdomains for: %s", target)
    dns_timeout = getattr(args, "dns_timeout", 3.0)
    max_workers = getattr(args, "dns_workers", 50)
    max_workers = max(4, min(200, int(max_workers)))
    subdomains = _enumerate_subdomains(target, wordlist, dns_timeout, max_workers=max_workers)
    record["subdomains"] = subdomains

    http_results: List[Dict] = []
    for sub in subdomains:
        for ip in sub.get("ips", []):
            probe_res = _probe_http(ip, getattr(args, "http_timeout", 3.0), getattr(args, "retries", 1))
            probe_res["fqdn"] = sub["fqdn"]
            http_results.append(probe_res)

    record["http_probes"] = http_results
    record["state"] = "active" if http_results else "inactive"
    return record


def run_recon_tasks(domains: List[str], wordlist: List[str], workers: int, args: Any) -> List[Dict]:
    """
    Manages the thread pool and queue to run all recon tasks.
    This is the main function called by main.py.
    """
    logger.info("Running recon tasks with %d workers", workers)
    task_q = queue.Queue()
    results: List[Dict] = []
    results_lock = threading.Lock()
    for domain in domains:
        task_q.put(domain)

    def worker_loop():
        """
        Target function for each thread.
        """
        while True:
            try:
                domain = task_q.get(block=False)
            except queue.Empty:
                return
            try:
                rec = _recon_one(domain, wordlist, args)
                logger.debug("scan %s -> %s", rec.get("domain"), rec.get("state"))
                with results_lock:
                    results.append(rec)
            finally:
                task_q.task_done()

    threads: List[threading.Thread] = []
    for _ in range(max(1, int(workers))):
        t = threading.Thread(target=worker_loop, daemon=True)
        t.start()
        threads.append(t)

    task_q.join()
    return results
