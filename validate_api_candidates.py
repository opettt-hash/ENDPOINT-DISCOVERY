#Coded By Rolandino
#!/usr/bin/env python3
"""
validate_api_candidates.py (enhanced)

Features:
 - Reads api_candidates.txt (tab-separated: URL in 3rd column usually)
 - Concurrently performs HEAD requests (follow redirects)
 - Optionally performs small GET sample when content-type suggests JSON or when --only-head not set
 - --workers N : concurrency level (default 4)
 - --only-head : do not perform GET samples, only HEAD
 - Generates curl checks for successful endpoints into curl_checks.sh (makes it easy to re-run manually)
 - Saves structured results to api_validation.json

Usage:
  python3 validate_api_candidates.py [--workers N] [--only-head]

Outputs:
  - api_validation.json : structured results
  - curl_checks.sh      : curl commands for 200 responses (HEAD/GET)
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time
import json
import os
import argparse

API_FILE = "api_candidates.txt"
OUT_FILE = "api_validation.json"
CURL_FILE = "curl_checks.sh"
USER_AGENT = "Mozilla/5.0 (compatible; EndpointValidator/1.0)"
HEADERS = {"User-Agent": USER_AGENT, "Accept": "*/*"}
TIMEOUT = 8
SAMPLE_BYTES = 1500
SLEEP_BETWEEN = 0.05

def read_urls(fname):
    urls = []
    if not os.path.exists(fname):
        print(f"[!] File not found: {fname}")
        return urls
    with open(fname, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].strip():
                url = parts[2].strip()
            else:
                url = parts[-1].strip()
            if url and (url.startswith("http://") or url.startswith("https://")):
                urls.append(url)
            else:
                # keep non-http lines as skipped entries
                urls.append({"raw": url})
    # dedupe preserving order
    seen = set()
    unique = []
    for u in urls:
        if isinstance(u, dict):
            key = ("raw", u.get("raw"))
        else:
            key = ("u", u)
        if key not in seen:
            seen.add(key)
            unique.append(u)
    # filter out the dict/skipped ones later
    return unique

def do_head(url):
    try:
        r = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return {"ok": True, "status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"ok": False, "error": f"HEAD error: {e}"}

def do_get_sample(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True, allow_redirects=True)
        # read up to SAMPLE_BYTES bytes from raw to avoid huge downloads
        sample = ""
        try:
            raw = r.raw.read(SAMPLE_BYTES)
            sample = raw.decode('utf-8', errors='replace')
        except Exception:
            sample = (r.text or "")[:SAMPLE_BYTES]
        return {"ok": True, "status": r.status_code, "headers": dict(r.headers), "sample": sample}
    except Exception as e:
        return {"ok": False, "error": f"GET error: {e}"}

def make_curl_head(url):
    # produce a curl -I command following redirects
    return f"curl -I -L -m {TIMEOUT} '{url}' -H 'User-Agent: {USER_AGENT}'"

def make_curl_get(url):
    return f"curl -s -L -m {TIMEOUT} '{url}' -H 'User-Agent: {USER_AGENT}' | head -c {SAMPLE_BYTES}"

def process_url(url, only_head=False):
    result = {"url": url, "head": None, "get": None}
    head = do_head(url)
    result["head"] = head
    # determine if we should GET
    ct = ""
    if head.get("ok"):
        ct = (head.get("headers") or {}).get("Content-Type", "")
    # if only_head flag true -> skip GET
    if only_head:
        return result
    # if content-type suggests JSON OR not present, do GET sample
    if (ct and "json" in ct.lower()) or not ct:
        get = do_get_sample(url)
        result["get"] = get
    return result

def main():
    parser = argparse.ArgumentParser(description="Validate API candidate URLs (concurrent).")
    parser.add_argument("--workers", "-w", type=int, default=4, help="Number of concurrent workers")
    parser.add_argument("--only-head", action="store_true", help="Do only HEAD requests (no GET samples)")
    parser.add_argument("--input", "-i", default=API_FILE, help="Input file (api_candidates.txt)")
    parser.add_argument("--out", "-o", default=OUT_FILE, help="Output JSON file")
    parser.add_argument("--curl-out", default=CURL_FILE, help="Output curl script for quick checks")
    args = parser.parse_args()

    global API_FILE, OUT_FILE, CURL_FILE
    API_FILE = args.input
    OUT_FILE = args.out
    CURL_FILE = args.curl_out

    items = read_urls(API_FILE)
    # filter valid urls, store skipped
    urls = []
    skipped = []
    for it in items:
        if isinstance(it, dict):
            skipped.append(it.get("raw"))
        else:
            urls.append(it)

    print(f"[+] Found {len(urls)} unique HTTP URLs to check (skipped {len(skipped)} non-http tokens).")
    results = []
    curl_lines = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(process_url, u, only_head=args.only_head): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"url": u, "head": {"ok": False, "error": str(e)}, "get": None}
            results.append(res)
            # generate curl for good responses
            head = res.get("head") or {}
            get = res.get("get") or {}
            status = head.get("status") if head.get("ok") else (get.get("status") if get.get("ok") else None)
            if status and isinstance(status, int) and status < 400:
                # prefer GET curl if we did GET, else HEAD curl
                if res.get("get") and res["get"].get("ok"):
                    curl_lines.append(make_curl_get(u))
                else:
                    curl_lines.append(make_curl_head(u))
            time.sleep(SLEEP_BETWEEN)

    # save JSON
    with open(OUT_FILE, "w", encoding="utf-8") as fw:
        json.dump({"checked_at": time.time(), "results": results, "skipped": skipped}, fw, indent=2, ensure_ascii=False)

    # write curl script
    if curl_lines:
        with open(CURL_FILE, "w", encoding="utf-8") as fc:
            fc.write("#!/bin/sh\n# Auto-generated curl checks (from validate_api_candidates.py)\n\n")
            for l in curl_lines:
                fc.write(l + "\n")
        try:
            os.chmod(CURL_FILE, 0o755)
        except Exception:
            pass

    # print summary
    total = len(results)
    ok_head = sum(1 for r in results if r.get("head") and r["head"].get("ok") and isinstance(r["head"].get("status"), int) and r["head"]["status"] < 400)
    json_get = sum(1 for r in results if r.get("get") and r["get"].get("ok") and "json" in ((r["get"].get("headers") or {}).get("Content-Type","").lower()))
    print(f"[+] Done. Checked {total} URLs. {ok_head} returned HEAD status <400.")
    print(f"[+] {json_get} returned JSON in GET sample.")
    if curl_lines:
        print(f"[+] curl checks saved to {CURL_FILE} ({len(curl_lines)} entries).")
    print(f"[+] Full structured output saved to {OUT_FILE}.")

if __name__ == "__main__":
    main()
