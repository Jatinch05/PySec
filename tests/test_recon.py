# tests/test_recon.py
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

# import functions to test
from tools.recon import main as recon_main
from tools.recon import workers as recon_workers



@pytest.fixture
def tmp_wordlist(tmp_path):
    p = tmp_path / "wl.txt"
    p.write_text("\n".join(["api", "www", "dev", "mail"]))
    return p


@pytest.fixture
def sample_args(tmp_path):
    return SimpleNamespace(
        domain=None,
        domains_file=None,
        wordlist=None,
        max_wordlist=1000,
        threads=None,
        http_timeout=1.0,
        dns_timeout=1.0,
        whois_timeout=1.0,
        retries=1,
        output=tmp_path / "out.json",
        dns_workers=4,
    )



def test_get_domains_single_domain():
    args = SimpleNamespace(domain=["example.com"], domains_file=None)
    domains = recon_main._get_domains(args)
    assert domains == ["example.com"]


def test_get_domains_from_file(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("example.com\ninvalid_domain\n127.0.0.1\n")
    args = SimpleNamespace(domain=None, domains_file=f)
    domains = recon_main._get_domains(args)
    assert "example.com" in domains
    assert "127.0.0.1" in domains


def test_load_wordlist_limit(tmp_wordlist):
    args = SimpleNamespace(wordlist=tmp_wordlist, max_wordlist=2)
    wl = recon_main._load_wordlist(args)
    assert len(wl) == 2
    assert wl[0] == "api"


def test_choose_worker_count_respects_user_request():
    args = SimpleNamespace(threads=2)
    workers = recon_main.choose_worker_count(args, total_tasks=10)
    assert workers == 2


def test_choose_worker_count_auto_limits():
    args = SimpleNamespace(threads=None)
    workers = recon_main.choose_worker_count(args, total_tasks=1)
    assert workers == 1


def test_run_recon_tasks_monkeypatched(monkeypatch):
   
    def fake_whois(target, timeout):
        return {"fake": True, "target": target}

    def fake_enumerate(domain, wordlist, timeout, max_workers=50, nameservers=None):
        
        return [
            {"fqdn": f"api.{domain}", "ips": ["1.2.3.4"], "state": "found"},
            {"fqdn": f"www.{domain}", "ips": ["5.6.7.8"], "state": "found"},
        ]

    def fake_probe(ip, timeout, retries):
        return {"url": f"http://{ip}", "status_code": 200, "final_url": f"http://{ip}/", "state": "up"}

    monkeypatch.setattr(recon_workers, "_get_whois", fake_whois)
    monkeypatch.setattr(recon_workers, "_enumerate_subdomains", fake_enumerate)
    monkeypatch.setattr(recon_workers, "_probe_http", fake_probe)

    args = SimpleNamespace(whois_timeout=1.0, dns_timeout=1.0, http_timeout=1.0, retries=1, dns_workers=4)
    results = recon_workers.run_recon_tasks(["example.com"], ["api", "www"], workers=1, args=args)

    assert isinstance(results, list)
    assert len(results) == 1
    rec = results[0]
    assert rec["target"] == "example.com"
    assert rec["domain"] == "example.com" or rec.get("domain") is None or rec.get("target") == "example.com"
    assert "whois" in rec
    assert isinstance(rec.get("subdomains", []), list)
    assert isinstance(rec.get("http_probes", []), list)
    assert any(p["state"] == "up" for p in rec.get("http_probes", []))



def test_main_writes_output_and_prints(monkeypatch, tmp_path, capsys):
    out_file = tmp_path / "out.json"
    args = SimpleNamespace(
        domain=["example.com"],
        domains_file=None,
        wordlist=None,
        max_wordlist=10,
        threads=1,
        http_timeout=1.0,
        dns_timeout=1.0,
        whois_timeout=0.5,
        retries=1,
        output=out_file,
        dns_workers=4,
    )

    fake_results = [
        {
            "target": "example.com",
            "domain": "example.com",
            "state": "inactive",
            "whois": {"registrar": "none"},
            "subdomains": [],
            "http_probes": [],
        }
    ]

    monkeypatch.setattr(recon_main, "get_args", lambda: args)
    monkeypatch.setattr(recon_workers, "run_recon_tasks", lambda domains, wordlist, workers, args: fake_results)

    (tmp_path / "logs").mkdir(exist_ok=True)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        recon_main.main()
    finally:
        os.chdir(cwd)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["domain"] == "example.com"

    captured = capsys.readouterr()
    assert "RECON SUMMARY" in captured.out or "RECON SUMMARY" in captured.err
