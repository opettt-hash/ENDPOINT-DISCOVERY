#Coded By Rolandino 
#!/usr/bin/env python3
"""
discover_endpoints_full.py (fixed)
Passive public endpoint discovery + curl examples + Burp CSV export + optional passive subdomain enumeration (crt.sh).
Fixed: resilient to invalid URLs (Invalid IPv6 URL) and skips malformed tokens.
Non-invasive: uses GET/HEAD only (and GET to crt.sh if requested).

Usage:
  python3 discover_endpoints_full.py https://dukcapil.kemendagri.go.id --workers 10 --max-pages 200 --subdomains

Outputs:
  - endpoints_report.json
  - burp_scan.csv
  - curl_examples.txt
"""
import argparse
import json
import re
import time
import csv
from urllib.parse import urlparse, urljoin, urlencode
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

# --------------- CONFIG ---------------
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; EndpointDiscovery/1.0; +https://example.local/)"
MAX_PAGES = 200
REQUESTS_SLEEP = 0.03
COMMON_API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/rest/", "/ajax/", "/wp-json/", "/graphql",
    "/search", "/sitemap.xml", "/feed", "/auth", "/login", "/logout", "/user",
    "/users", "/v1/", "/v2/", "/public/api", "/backend", "/portal", "/blog/search_submit"
]
URL_LIKE_RE = re.compile(r'(https?://[^\s"\'<>]+|/[_a-zA-Z0-9\-\./\?&=%:#]+)')
JS_URL_RE = re.compile(r"""(?:"|')(https?://[^"'\\\s]+)|(?:"|')(/[^"'\\\s]+)""")
# --------------------------------------

session = requests.Session()
session.headers.update({"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"})

def fetch(url, method="GET", timeout=8, allow_redirects=True):
    try:
        r = session.request(method, url, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

def same_host(a, b):
    try:
        return urlparse(a).netloc == urlparse(b).netloc
    except Exception:
        return False

def safe_normalize(base, link):
    try:
        if not link:
            return None
        # basic sanitization: strip whitespace and surrounding brackets which break urlparse
        s = str(link).strip()
        # remove matching square brackets that sometimes appear in JS tokens
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
        # filter javascript: handlers
        if s.startswith("javascript:") or s.lower().startswith("data:"):
            return None
        return urljoin(base, s)
    except Exception:
        return None

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    forms = []
    # anchors
    for a in soup.find_all("a", href=True):
        n = safe_normalize(base_url, a["href"])
        if n:
            links.add(n)
    # forms
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "GET").upper()
        inputs = []
        for inp in f.find_all(["input","textarea","select"]):
            name = inp.get("name")
            t = inp.get("type") or inp.name
            value = inp.get("value") or ""
            if name:
                inputs.append({"name": name, "type": t, "value": value})
        normalized_action = safe_normalize(base_url, action)
        forms.append({"action": normalized_action or base_url, "method": method, "inputs": inputs})
        if normalized_action:
            links.add(normalized_action)
    # scripts, links, imgs
    for s in soup.find_all("script", src=True):
        n = safe_normalize(base_url, s["src"])
        if n:
            links.add(n)
    for l in soup.find_all("link", href=True):
        n = safe_normalize(base_url, l["href"])
        if n:
            links.add(n)
    for img in soup.find_all("img", src=True):
        n = safe_normalize(base_url, img["src"])
        if n:
            links.add(n)
    # meta refresh
    for m in soup.find_all("meta", attrs={"http-equiv":"refresh"}):
        c = m.get("content","")
        if "url=" in c.lower():
            u = c.split("url=")[-1]
            n = safe_normalize(base_url, u)
            if n:
                links.add(n)
    # inline JS url-like tokens
    for script in soup.find_all("script"):
        txt = script.string or ""
        for u in URL_LIKE_RE.findall(txt):
            n = safe_normalize(base_url, u)
            if n:
                links.add(n)
    return links, forms

def extract_urls_from_js(js_text, base_url):
    found = set()
    if not js_text:
        return found
    for m in URL_LIKE_RE.findall(js_text):
        u = m
        if not u:
            continue
        n = safe_normalize(base_url, u)
        if n:
            found.add(n)
    for m in JS_URL_RE.findall(js_text):
        full, rel = m
        if full:
            n = safe_normalize(base_url, full)
            if n:
                found.add(n)
        elif rel:
            n = safe_normalize(base_url, rel)
            if n:
                found.add(n)
    return {u for u in found if u}

def probe_url(url, timeout=6):
    res = {"url": url, "status": None, "content_type": None, "length": None, "ok": False}
    try:
        r = fetch(url, method="HEAD", timeout=timeout)
        if r is None:
            return res
        res["status"] = r.status_code
        res["content_type"] = r.headers.get("Content-Type")
        res["length"] = r.headers.get("Content-Length")
        res["ok"] = r.ok
    except Exception:
        # leave defaults
        pass
    return res

def build_curl_for_form(form):
    """
    Build a sample curl command for a discovered form.
    """
    if not form or not form.get("action"):
        return None
    action = form["action"]
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])
    headers = [
        "-H 'User-Agent: {}'".format(DEFAULT_USER_AGENT),
        "-H 'Accept: */*'"
    ]
    if method == "GET":
        params = {}
        for i in inputs:
            params[i["name"]] = i.get("value") or f"sample_{i['name']}"
        query = urlencode(params)
        curl = f"curl -G '{action}' -s {' '.join(headers)} --data '{query}'"
        return curl
    else:
        data = {}
        for i in inputs:
            data[i["name"]] = i.get("value") or f"sample_{i['name']}"
        body = urlencode(data)
        curl = f"curl -X POST '{action}' -s {' '.join(headers)} -d '{body}'"
        return curl

def passive_crtsh_subdomains(domain):
    """
    Passive subdomain enumeration using crt.sh JSON output.
    Note: crt.sh may limit requests; use responsibly.
    """
    out = set()
    try:
        q = f"%25.{domain}"  # %25 == %
        url = f"https://crt.sh/?q={q}&output=json"
        r = fetch(url, method="GET", timeout=15)
        if r and r.status_code == 200:
            try:
                data = r.json()
                for item in data:
                    name = item.get("name_value") or ""
                    if name:
                        for line in name.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            # sanitize
                            if line.startswith("*."):
                                line = line[2:]
                            # ensure it's a hostname-like token
                            if " " in line or "/" in line:
                                continue
                            # form https URL
                            scheme = "https://"
                            if line.startswith("http://") or line.startswith("https://"):
                                out.add(line)
                            else:
                                out.add(scheme + line)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(out)

def is_valid_http_url(u):
    """Validate URL for http/https scheme and netloc, resilient to ValueError."""
    if not u or not isinstance(u, str):
        return False
    s = u.strip()
    try:
        # remove stray surrounding brackets like "[example]" that break urlparse
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
        parsed = urlparse(s)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True

def discover(start_url, max_pages=MAX_PAGES, workers=8, timeout=8, do_subdomains=False):
    parsed_start = urlparse(start_url)
    base_origin = f"{parsed_start.scheme}://{parsed_start.netloc}"
    seen = set()
    to_crawl = deque([start_url])
    discovered_candidates = set()
    js_candidates = set()
    form_list = []
    robots_text = ""
    sitemap_urls = set()
    skipped_invalid_count = 0

    # robots
    robots_url = urljoin(base_origin, "/robots.txt")
    r = fetch(robots_url, method="GET", timeout=timeout)
    if r and r.status_code == 200:
        robots_text = r.text
        for line in robots_text.splitlines():
            if ":" in line:
                parts = line.split(":",1)[1].strip()
                if parts:
                    n = safe_normalize(base_origin, parts)
                    if n:
                        discovered_candidates.add(n)

    # sitemap
    sitemap_url = urljoin(base_origin, "/sitemap.xml")
    r2 = fetch(sitemap_url, method="GET", timeout=timeout)
    if r2 and r2.status_code == 200:
        for m in re.findall(r"<loc>([^<]+)</loc>", r2.text):
            u = m.strip()
            if u:
                sitemap_urls.add(u)
                discovered_candidates.add(u)

    # BFS crawl
    while to_crawl and len(seen) < max_pages:
        url = to_crawl.popleft()
        if not url or url in seen:
            continue
        seen.add(url)
        r = fetch(url, method="GET", timeout=timeout)
        if r is None:
            continue
        html = r.text or ""
        links, forms = extract_links(html, url)
        for f in forms:
            form_list.append(f)
        for l in links:
            if not l:
                continue
            discovered_candidates.add(l)
            try:
                if same_host(base_origin, l) and l not in seen and l not in to_crawl:
                    if urlparse(l).scheme in ("http","https"):
                        to_crawl.append(l)
            except Exception:
                # if parsing fails, skip
                continue
        # script src
        soup = BeautifulSoup(html, "html.parser")
        for s in soup.find_all("script", src=True):
            js = safe_normalize(url, s["src"])
            if js:
                js_candidates.add(js)

    # fetch JS and scan
    js_found_urls = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fetch, js, "GET", timeout): js for js in list(js_candidates)[:300]}
        for fut in as_completed(futures):
            js = futures[fut]
            r = None
            try:
                r = fut.result()
            except Exception:
                r = None
            if r and r.status_code == 200:
                try:
                    urls = extract_urls_from_js(r.text, base_origin)
                    for u in urls:
                        if u:
                            js_found_urls.add(u)
                            discovered_candidates.add(u)
                except Exception:
                    pass

    # add common API paths
    for p in COMMON_API_PATHS:
        n = urljoin(base_origin, p)
        discovered_candidates.add(n)

    # optional passive subdomain enumeration
    subdomains = []
    if do_subdomains:
        domain = parsed_start.netloc
        print(f"[+] Performing passive subdomain search via crt.sh for {domain} (read-only)...")
        subdomains = passive_crtsh_subdomains(domain)
        for s in subdomains:
            discovered_candidates.add(s)

    # filter candidates into valid http(s) URLs
    candidates = []
    for c in discovered_candidates:
        if not c:
            continue
        # quick sanitization
        c_str = str(c).strip()
        # skip javascript/data tokens etc
        if c_str.lower().startswith("javascript:") or c_str.lower().startswith("data:"):
            skipped_invalid_count += 1
            continue
        # remove stray brackets
        if c_str.startswith("[") and c_str.endswith("]"):
            c_str = c_str[1:-1].strip()
        if is_valid_http_url(c_str):
            candidates.append(c_str)
        else:
            skipped_invalid_count += 1

    # probe candidates
    probe_results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_url, u, timeout): u for u in candidates}
        for f in as_completed(futs):
            u = futs[f]
            try:
                res = f.result()
            except Exception:
                res = {"url": u, "status": None, "ok": False}
            probe_results.append(res)
            time.sleep(REQUESTS_SLEEP)

    # prepare curl examples from forms and some top endpoints
    curl_examples = []
    for fm in form_list:
        c = build_curl_for_form(fm)
        if c:
            curl_examples.append({"type": "form", "action": fm["action"], "method": fm["method"], "curl": c})

    # add curl GET example for top HTTP 200 endpoints
    good_probes = sorted([p for p in probe_results if p.get("status") and p["status"] < 400], key=lambda x: (x.get("status") or 999, x.get("url")))
    for pr in good_probes[:50]:
        curl_examples.append({"type": "probe", "url": pr["url"], "curl": f"curl -I '{pr['url']}' -s -H 'User-Agent: {DEFAULT_USER_AGENT}'"})

    # assemble report
    report = {
        "start_url": start_url,
        "base_origin": base_origin,
        "crawled_pages_count": len(seen),
        "discovered_candidates_count": len(candidates),
        "skipped_invalid_tokens": skipped_invalid_count,
        "robots_txt": robots_text,
        "sitemap_urls": list(sorted(sitemap_urls)),
        "forms": form_list,
        "js_files": list(sorted(js_candidates)),
        "js_found_urls": list(sorted(js_found_urls)),
        "probe_results": probe_results,
        "curl_examples": curl_examples,
        "subdomains_passive": subdomains,
        "timestamp": time.time()
    }
    return report

def save_outputs(report, out_prefix="endpoints_report"):
    json_path = f"{out_prefix}.json"
    csv_path = f"burp_scan.csv"
    curl_path = f"curl_examples.txt"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # burp CSV: method,url,status,content_type,length
    with open(csv_path, "w", newline='', encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["method_or_probe","url","status","content_type","length"])
        for p in sorted(report["probe_results"], key=lambda x: (x.get("status") or 999, x.get("url"))):
            w.writerow(["PROBE", p.get("url"), p.get("status"), p.get("content_type"), p.get("length")])
        # add forms as POST/GET hints
        for fm in report.get("forms", []):
            w.writerow([fm.get("method","GET"), fm.get("action"), "", "", ""])

    # curl examples
    with open(curl_path, "w", encoding="utf-8") as f:
        f.write("# Curl examples generated by discover_endpoints_full.py\n\n")
        for c in report.get("curl_examples", []):
            if c.get("type") == "form":
                f.write(f"# Form - {c.get('method')} {c.get('action')}\n{c.get('curl')}\n\n")
            else:
                f.write(f"# Probe - {c.get('url')}\n{c.get('curl')}\n\n")

    return json_path, csv_path, curl_path

def main():
    p = argparse.ArgumentParser(description="Passive public endpoint discovery (full, fixed).")
    p.add_argument("start_url", help="Start URL (include http/https)")
    p.add_argument("--max-pages", type=int, default=MAX_PAGES)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--subdomains", action="store_true", help="Enable passive subdomain enumeration via crt.sh (read-only)")
    p.add_argument("--out-prefix", default="endpoints_report")
    args = p.parse_args()

    start = args.start_url
    if not start.startswith("http"):
        print("Provide full URL (http/https).")
        return
    print(f"[+] Starting passive discovery on {start}")
    report = discover(start, max_pages=args.max_pages, workers=args.workers, timeout=args.timeout, do_subdomains=args.subdomains)
    json_path, csv_path, curl_path = save_outputs(report, out_prefix=args.out_prefix)
    # print summary
    print(f"[+] Report saved: {json_path}")
    print(f"[+] Burp CSV saved: {csv_path}")
    print(f"[+] Curl examples saved: {curl_path}")
    print(f"[+] Crawled pages: {report['crawled_pages_count']}")
    oks = [p for p in report["probe_results"] if p.get("status") and p["status"] < 400]
    print(f"[+] Up (status < 400): {len(oks)}")
    print(f"[+] Skipped invalid tokens: {report.get('skipped_invalid_tokens',0)}")
    print("[+] Top 20 discovered endpoints (status, url):")
    for r in sorted(report["probe_results"], key=lambda x: (x.get("status") or 999, x.get("url")))[:20]:
        print(f" - {r.get('status')} {r.get('url')} ({r.get('content_type')})")

if __name__ == "__main__":
    main()
