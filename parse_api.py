Coded By Rolandino 
#!/usr/bin/env python3
"""
parse_api.py (fixed)
Scan endpoints_report.json produced by discover_endpoints_full.py
and extract likely API endpoints into api_candidates.txt

Checks:
 - probe_results entries with content_type containing "application/json"
 - URLs containing common API keywords: /api, /service, /rest, /graphql, /v1/, /v2/
 - form actions that look like API endpoints
 - JS-extracted URLs and passive subdomains
Outputs:
 - api_candidates.txt (tab separated: source\tstatus(if any)\turl\tcontent_type/hint)
 - prints summary to stdout
"""
import json
import re

API_KEYWORDS = ["/api/", "/api.", "/service/", "/rest/", "/graphql", "/v1/", "/v2/", "/_api", "/public/api", "/ajax/"]

def looks_like_api_url(u: str) -> bool:
    if not u:
        return False
    u_l = u.lower()
    for k in API_KEYWORDS:
        if k in u_l:
            return True
    # also match query-like JSON endpoints e.g. ?format=json or .json suffix
    if u_l.endswith(".json") or "format=json" in u_l:
        return True
    return False

def main():
    infile = "endpoints_report.json"
    outfile = "api_candidates.txt"
    try:
        with open(infile, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to open {infile}: {e}")
        return

    candidates = []
    seen = set()

    # 1) probe_results (has status & content_type)
    for p in data.get("probe_results", []):
        url = p.get("url") or ""
        ctype = (p.get("content_type") or "").lower()
        status = p.get("status") or ""
        # content-type indicates JSON
        if "application/json" in ctype or "json" in ctype:
            key = f"probe::{url}"
            if key not in seen:
                candidates.append(("probe", status, url, ctype))
                seen.add(key)
        # url pattern
        if looks_like_api_url(url):
            key = f"probe::{url}"
            if key not in seen:
                candidates.append(("probe", status, url, ctype))
                seen.add(key)

    # 2) forms (action + method)
    for f in data.get("forms", []):
        action = f.get("action") or ""
        method = f.get("method") or ""
        if looks_like_api_url(action):
            key = f"form::{action}"
            if key not in seen:
                candidates.append(("form", method, action, "form"))
                seen.add(key)

    # 3) js_found_urls
    for u in data.get("js_found_urls", []):
        if looks_like_api_url(u):
            key = f"js::{u}"
            if key not in seen:
                candidates.append(("js", "", u, "js_extracted"))
                seen.add(key)

    # 4) subdomains_passive
    for u in data.get("subdomains_passive", []):
        if looks_like_api_url(u):
            key = f"sub::{u}"
            if key not in seen:
                candidates.append(("subdomain", "", u, "passive"))
                seen.add(key)

    # 5) fallback: search all probe urls for "/api" substring (safety)
    # already mostly covered but include search through sitemap_urls too
    for u in data.get("sitemap_urls", []):
        if looks_like_api_url(u):
            key = f"smap::{u}"
            if key not in seen:
                candidates.append(("sitemap", "", u, "sitemap"))
                seen.add(key)

    # write out
    with open(outfile, "w", encoding="utf-8") as out:
        out.write("# source\tstatus/method\turl\thint\n")
        for src, status, url, hint in candidates:
            out.write(f"{src}\t{status}\t{url}\t{hint}\n")

    print(f"[+] Found {len(candidates)} possible API endpoints")
    print(f"[+] Saved to {outfile}")
    if len(candidates) > 0:
        print("[+] Sample:")
        for src, status, url, hint in candidates[:20]:
            print(f" - {src}\t{status}\t{url}\t{hint}")

if __name__ == "__main__":
    main()
