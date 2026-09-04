#!/usr/bin/env python3
"""Websites dataset for the Fleet Globe, built on the box from Traefik's access logs.

No Google auth, no cookies: a visitor is a distinct client IP (hashed, never stored raw) seen on a
public site, once bots, crawlers and vulnerability scanners are removed. Location comes from the
GeoLite2-City database (P3TERX mirror), device from the User-Agent (Mobile vs Desktop).

Runs hourly from cron. Each rotated log file is parsed once into /var/lib/globe-web/days/<date>.json
(final); today's live log is re-parsed on every run. The 90-day merge is POSTed to the globe app's
/ingest endpoint (basic auth) which serves it as /data-web.json.

Config: /etc/globe-web.conf (root 600): GLOBE_URL, GLOBE_USER, GLOBE_PASSWORD.
"""
import base64, glob, gzip, hashlib, json, os, re, sys, time, urllib.request
from datetime import date, datetime, timedelta

import maxminddb

LOGDIR = "/data/coolify/proxy"
STATE = "/var/lib/globe-web"
DAYS_DIR = os.path.join(STATE, "days")
MMDB = os.path.join(STATE, "GeoLite2-City.mmdb")
CONF = "/etc/globe-web.conf"
WINDOW = int(os.environ.get("GLOBE_DAYS", "90"))
NEW_LOOKBACK = 30          # a visitor is "first-time" if not seen on that site in the previous 30 days

# host suffix -> (site id, label, colour). www. is stripped first; api.fitexercisedb.com folds into
# fitexercisedb. Colours continue the mobile palette (dataviz dark surface).
SITES = [
    ("inventoria-app.com", "inventoria",   "InventorIA",     "#3987e5"),
    ("maison-soleil.shop", "maisonsoleil", "Maison Soleil",  "#d95926"),
    ("fitexercisedb.com",  "fitexercisedb","FitExerciseDB",  "#199e70"),
    ("stayfit-app.com",    "stayfit",      "StayFit site",   "#e66767"),
    ("astralpdf.com",      "astralpdf",    "Astral PDF",     "#9085e9"),
    ("astraljson.com",     "astraljson",   "Astral JSON",    "#c98500"),
    ("astraltext.com",     "astraltext",   "Astral Text",    "#d55181"),
    ("astralbatch.com",    "astralbatch",  "Astral Batch",   "#008300"),
    ("momentos.life",      "momentos",     "Momentos",       "#0fa3b1"),
    ("taoufikjabbari.dev", "taoufik",      "taoufikjabbari.dev", "#a06a2c"),
]
BOT_RE = re.compile(r"bot|crawl|spider|slurp|bingpreview|facebookexternalhit|headless|lighthouse|monitor|uptime|curl|wget|python-requests|semrush|ahrefs|mj12|googlebot|google-inspectiontool|storebot-google", re.I)
SCAN_RE = re.compile(r"^/(wp-|wordpress|xmlrpc\.php|\.env|\.git|phpmyadmin|admin\.php|vendor/|cgi-bin/|\.well-known/traffic-advice|owa/|autodiscover)|\.php(\?|$)", re.I)
MOBILE_RE = re.compile(r"Mobile|Android|iPhone|iPad|iPod", re.I)
PAGE_RE = re.compile(r"^/[^.?]*(\.html?)?(\?.*)?$")   # a page, not an asset


def site_of(host):
    h = (host or "").lower().split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    if h == "legal.taoufikjabbari.dev":
        return None
    for suffix, sid, _, _ in SITES:
        if h == suffix or h.endswith("." + suffix):
            return sid
    return None


def ip_hash(ip):
    return hashlib.sha1(("globe:" + ip).encode()).hexdigest()[:12]


def parse(path, reader):
    """-> {date: {site: {"cells": {key: {"ips": set, "pv": n}}, "ips": set}}}"""
    out = {}
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            sid = site_of(r.get("RequestHost"))
            if not sid:
                continue
            ua = r.get("request_User-Agent") or ""
            if not ua or BOT_RE.search(ua):
                continue
            path_ = (r.get("RequestPath") or "/")
            if SCAN_RE.search(path_):
                continue
            st = int(r.get("DownstreamStatus") or 0)
            if st >= 400:
                continue
            ip = r.get("request_Cf-Connecting-Ip") or r.get("ClientHost") or ""
            if not ip or ip.startswith("10.") or ip.startswith("172.1") or ip.startswith("192.168."):
                continue
            day = (r.get("StartUTC") or "")[:10]
            if len(day) != 10:
                continue
            try:
                g = reader.get(ip) or {}
            except Exception:
                g = {}
            loc = g.get("location") or {}
            if "latitude" not in loc:
                continue
            cc = (g.get("country") or {}).get("iso_code") or ""
            country = ((g.get("country") or {}).get("names") or {}).get("en") or cc
            city = ((g.get("city") or {}).get("names") or {}).get("en") or ""
            device = "Mobile" if MOBILE_RE.search(ua) else "Desktop"
            key = "|".join([device, str(round(loc["latitude"], 2)), str(round(loc["longitude"], 2)), city, cc, country])
            d = out.setdefault(day, {}).setdefault(sid, {"cells": {}, "ips": set()})
            cell = d["cells"].setdefault(key, {"ips": set(), "pv": 0})
            h = ip_hash(ip)
            cell["ips"].add(h); d["ips"].add(h)
            if PAGE_RE.match(path_):
                cell["pv"] += 1
    return out


def day_file(day):
    return os.path.join(DAYS_DIR, day + ".json")


def save_day(day, sites, final):
    doc = {"day": day, "final": final, "sites": {}}
    for sid, d in sites.items():
        doc["sites"][sid] = {"ips": sorted(d["ips"]),
                             "cells": {k: {"ips": sorted(c["ips"]), "pv": c["pv"]} for k, c in d["cells"].items()}}
    tmp = day_file(day) + ".tmp"
    json.dump(doc, open(tmp, "w"), separators=(",", ":"))
    os.replace(tmp, day_file(day))


def load_day(day):
    try:
        return json.load(open(day_file(day)))
    except (OSError, ValueError):
        return None


def refresh_days(reader):
    """Parse the rotated files that have no final day file yet, and today's live log."""
    files = sorted(glob.glob(os.path.join(LOGDIR, "access.log.*")), key=lambda p: int(re.search(r"\.log\.(\d+)", p).group(1)), reverse=True)
    today = date.today().isoformat()
    for path in files + [os.path.join(LOGDIR, "access.log")]:
        live = path.endswith("access.log")
        # a rotated file covers one day (rotation at 00:00); skip it if that day is already final
        n = None if live else int(re.search(r"\.log\.(\d+)", path).group(1))
        expect = None if live else (date.today() - timedelta(days=n)).isoformat()
        if expect and (load_day(expect) or {}).get("final"):
            continue
        t0 = time.time()
        parsed = parse(path, reader)
        for day, sites in parsed.items():
            existing = load_day(day)
            if existing and existing.get("final") and not live:
                continue
            final = (not live) and day != today
            if existing and not final and day != today and existing.get("final"):
                continue
            save_day(day, sites, final)
        print(f"parsed {os.path.basename(path)} in {time.time() - t0:.1f}s: days {sorted(parsed)}", file=sys.stderr)


def build():
    days = sorted(p[:-5] for p in os.listdir(DAYS_DIR) if p.endswith(".json"))
    days = [d for d in days if d >= (date.today() - timedelta(days=WINDOW + NEW_LOOKBACK)).isoformat()]
    docs = {d: load_day(d) for d in days}
    seen = {sid: {} for _, sid, _, _ in SITES}        # sid -> {iphash: last day seen}
    points, rows = [], {sid: 0 for _, sid, _, _ in SITES}
    cutoff = (date.today() - timedelta(days=WINDOW)).isoformat()
    for d in days:
        doc = docs.get(d) or {}
        for sid, sd in (doc.get("sites") or {}).items():
            if sid not in seen:
                continue
            lookback = (date.fromisoformat(d) - timedelta(days=NEW_LOOKBACK)).isoformat()
            known = seen[sid]
            for key, cell in sd["cells"].items():
                new = sum(1 for h in cell["ips"] if known.get(h, "") < lookback)
                if d >= cutoff:
                    device, lat, lng, city, cc, country = key.split("|")
                    points.append({"a": sid, "d": d.replace("-", ""), "lat": float(lat), "lng": float(lng), "city": city,
                                   "cc": cc, "country": country, "p": device, "u": len(cell["ips"]), "n": new, "r": cell["pv"]})
                    rows[sid] += 1
            for h in sd["ips"]:
                known[h] = d
    return {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "days": WINDOW,
            "source": "Traefik access logs + GeoLite2", "noun": "site", "platforms": ["Desktop", "Mobile"],
            "metrics": {"u": "Visitors", "n": "First-time visitors", "r": "Page views"},
            "metrics_short": {"u": "Visitors", "n": "First-time", "r": "Page views"},
            "excluded": "bots, crawlers (Googlebot included) and vulnerability scanners are not counted; a visitor is a distinct IP per day",
            "apps": [{"id": sid, "name": name, "color": col} for _, sid, name, col in SITES],
            "rows_per_app": rows, "points": points}


def post(doc):
    conf = {}
    for line in open(CONF):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); conf[k] = v.strip().strip('"')
    url = conf["GLOBE_URL"].rstrip("/") + "/ingest"
    auth = base64.b64encode(f"{conf['GLOBE_USER']}:{conf['GLOBE_PASSWORD']}".encode()).decode()
    body = json.dumps(doc, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read().decode()[:80]


def main():
    os.makedirs(DAYS_DIR, exist_ok=True)
    reader = maxminddb.open_database(MMDB)
    refresh_days(reader)
    doc = build()
    json.dump(doc, open(os.path.join(STATE, "data-web.json"), "w"), separators=(",", ":"))
    print(f"built {len(doc['points'])} points, rows per site {doc['rows_per_app']}", file=sys.stderr)
    try:
        print("ingest:", post(doc), file=sys.stderr)
    except Exception as e:
        print("ingest failed (kept locally, next run retries):", e, file=sys.stderr)


if __name__ == "__main__":
    main()
