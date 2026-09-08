#!/usr/bin/env python3
"""fleet-journeys.py: what humans DID on the web fleet, session by session.

Reads the Traefik access logs (JSON, /data/coolify/proxy/access.log*), rebuilds one session per
(client IP, User-Agent) per site with a 30 min gap, keeps the ones that look human (a page AND an
asset, or in-app API calls), tags crawlers by their walk pattern (many pages in a minute, every
locale root, the legal/robots/ads/llms set), and records for each session: when, where (GeoLite2
city), device, language, source (Referer), the ordered page path, duration, API calls, error
statuses and conversion events (signup, login, demo, pricing, checkout, contact, download...).

InventorIA in-app actions (new users, activity log by workspace, e2e/demo excluded) are pulled
from its Postgres container so the app side sits next to the site side.

Output: /var/lib/globe-web/journeys/<day>.json (one per day, last 7 days rebuilt each run, the
current day partial) + journeys-web.json (all days) posted to the Fleet Globe at /ingest-journeys.
`--day YYYY-MM-DD --text` prints the human-readable summary used by the 12:00 traffic report.

Taoufik, 06/09/2026: "You should be able to know anything that users do in our website fleets.
So we analyze their behaviours."
"""
import base64
import collections
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import urllib.request

import maxminddb

LOGS = sorted(glob.glob("/data/coolify/proxy/access.log*"))
STATE = "/var/lib/globe-web"
OUT = os.path.join(STATE, "journeys")
MMDB = os.path.join(STATE, "GeoLite2-City.mmdb")
CONF = "/etc/globe-web.conf"
DAYS = 7
GAP = dt.timedelta(minutes=30)

SITES = [
    ("inventoria-app.com", "inventoria", "InventorIA"),
    ("maison-soleil.shop", "maisonsoleil", "Maison Soleil"),
    ("fitexercisedb.com", "fitexercisedb", "FitExerciseDB"),
    ("stayfit-app.com", "stayfit", "StayFit site"),
    ("astralpdf.com", "astralpdf", "Astral PDF"),
    ("astraljson.com", "astraljson", "Astral JSON"),
    ("astraltext.com", "astraltext", "Astral Text"),
    ("astralbatch.com", "astralbatch", "Astral Batch"),
    ("momentos.life", "momentos", "Momentos"),
    ("taoufikjabbari.dev", "taoufik", "taoufikjabbari.dev"),
]
BOT_RE = re.compile(r"bot|crawl|spider|slurp|bingpreview|facebookexternalhit|headless|lighthouse|monitor|uptime|curl|wget|python|go-http|java/|okhttp|scan|checker|validator|semrush|ahrefs|mj12|google-inspectiontool|storebot-google|playwright|chrome-lighthouse|node-fetch|axios|libwww", re.I)
SCAN_RE = re.compile(r"/(wp-|wordpress|xmlrpc\.php|\.env|\.git|\.aws|\.ssh|\.docker|phpmyadmin|admin\.php|administrator|backoffice|vendor/|cgi-bin/|owa/|autodiscover|console/?$|server-status|_catalog|cpanel|whm|actuator|\.well-known/traffic-advice|com_jce|internal/?$|secure/?$)|credentials|config\.(json|yml|yaml)|%22|\.php(\?|$)|\.(bak|sql|tar|gz|zip)$", re.I)
ASSET_RE = re.compile(r"\.(js|mjs|css|png|jpe?g|webp|avif|gif|svg|ico|woff2?|ttf|map|xml|txt|json|webmanifest)(\?|$)|^/_next/|^/static/|^/(icon|apple-icon|favicon|opengraph-image|twitter-image|manifest)\b", re.I)
API_RE = re.compile(r"^/(backend/|api/)")
LOCALE_RE = re.compile(r"^/(en|fr|es|de|pt|zh|it|ja|ru|ar|nl|ko|hi|tr|pl)(/|$)")
LEGAL_SET = {"/terms", "/privacy", "/robots.txt", "/ads.txt", "/llms.txt", "/sitemap.xml", "/humans.txt", "/security.txt", "/.well-known/security.txt"}
MOBILE_RE = re.compile(r"Mobile|Android|iPhone|iPad|iPod", re.I)
ASN_TSV = os.path.join(STATE, "ip2asn-combined.tsv")   # https://iptoasn.com/data/ip2asn-combined.tsv.gz
HOSTING_RE = re.compile(r"amazon|aws|google|microsoft|azure|digitalocean|hetzner|ovh|linode|akamai|oracle|alibaba|aliyun|tencent|huawei|vultr|choopa|constant|contabo|m247|leaseweb|cloudflare|fastly|scaleway|online s\.a|ionos|godaddy|hostinger|hosting|cloud|server|datacenter|data center|vps|colo|packet|equinix|zenlayer|cogent|psychz|quadranet|hostwinds|kamatera|upcloud|exoscale|g-core|gcore|stackpath|limelight|edgecast|censys|shodan|palo alto|zscaler|netskope|forcepoint|ip volume|ipvolume|worldstream|serverion|hostpapa|namecheap|dedipath|hivelocity|rackspace|softlayer|ibm|salesforce|umbrella|carinet|censys|netcraft|urlscan|virustotal|tor ", re.I)
PRIVATE_RELAY_RE = re.compile(r"cloudflare|akamai|fastly|apple", re.I)   # iCloud Private Relay egress: a real Safari user behind a CDN ASN


class AsnTable:
    """Sorted ranges from ip2asn-combined.tsv: start end asn country name."""

    def __init__(self, path):
        self.starts, self.rows = [], []
        try:
            for line in open(path, errors="replace"):
                a, b, asn, cc, name = line.rstrip("\n").split("\t", 4)
                try:
                    self.starts.append(int(ipaddress.ip_address(a)))
                    self.rows.append((int(ipaddress.ip_address(b)), int(asn), name))
                except ValueError:
                    continue
        except OSError:
            pass
        # v4 and v6 sort into two disjoint int spaces; keep one sorted list
        order = sorted(range(len(self.starts)), key=self.starts.__getitem__)
        self.starts = [self.starts[i] for i in order]
        self.rows = [self.rows[i] for i in order]

    def lookup(self, ip):
        import bisect
        try:
            n = int(ipaddress.ip_address(ip))
        except ValueError:
            return (0, "")
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and self.rows[i][0] >= n and self.rows[i][1] != 0:
            return (self.rows[i][1], self.rows[i][2])
        return (0, "")

# path -> conversion event, per site family (checked in order, first match wins)
EVENTS = [
    (re.compile(r"^/(signup|register|inscription)"), "signup"),
    (re.compile(r"^/(login|signin|connexion)"), "login"),
    (re.compile(r"^/demo"), "demo"),
    (re.compile(r"^/(pricing|tarifs|precios|preise)"), "pricing"),
    (re.compile(r"^/(checkout|commande|panier|cart|billing|subscribe|abonnement)"), "checkout"),
    (re.compile(r"^/(contact|support)"), "contact"),
    (re.compile(r"^/(download|telecharger|get-the-app|app-store|play-store)"), "download"),
    (re.compile(r"^/(dashboard|assets|people|licenses|contracts|settings)"), "in-app"),
    (re.compile(r"^/(oeuvre|collection|en/oeuvre|en/collection)/"), "product"),
    (re.compile(r"^/(blog|articles?)(/|$)"), "blog"),
    (re.compile(r"^/(marketplace|exercises?)"), "catalog"),
]
TOOL_API_RE = re.compile(r"^/api/(convert|compress|merge|split|batch|remove-background|format|validate|compare|diff|ocr|extract)")


def conf():
    c = {}
    try:
        for line in open(CONF):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                c[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return c


def excluded_networks(c):
    nets = []
    for x in (c.get("EXCLUDE_IPS") or "").split(","):
        x = x.strip()
        if not x:
            continue
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return nets


def site_of(host):
    h = (host or "").lower().split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    if h == "legal.taoufikjabbari.dev" or h.startswith("api."):
        return None
    for suffix, sid, _ in SITES:
        if h == suffix or h.endswith("." + suffix):
            return sid
    return None


def ip_hash(ip):
    return hashlib.sha1(("journeys:" + ip).encode()).hexdigest()[:10]


def device_of(ua):
    os_ = "other"
    for k, rx in (("iOS", r"iPhone|iPad|iPod"), ("Android", r"Android"), ("Windows", r"Windows"), ("macOS", r"Macintosh"), ("Linux", r"Linux|X11")):
        if re.search(rx, ua):
            os_ = k
            break
    return ("mobile" if MOBILE_RE.search(ua) else "desktop"), os_


def source_of(ref, site_host):
    if not ref:
        return ""
    m = re.match(r"https?://([^/]+)", ref)
    if not m:
        return ""
    h = m.group(1).lower()
    if h.startswith("www."):
        h = h[4:]
    if h == site_host or h.endswith("." + site_host):
        return ""
    return h


def read_rows(days_wanted):
    """Yield (day, site, ip, ua, ts, path, status, referer, lang) for the wanted days."""
    for fn in LOGS:
        try:
            f = open(fn, errors="replace")
        except OSError:
            continue
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            t = r.get("StartUTC", "")
            day = t[:10]
            if day not in days_wanted:
                continue
            site = site_of(r.get("RequestHost"))
            if not site:
                continue
            yield (day, site, r.get("ClientHost") or "", r.get("request_User-Agent") or "", t[:19],
                   r.get("RequestPath") or "/", int(r.get("DownstreamStatus") or 0),
                   r.get("request_Referer") or "", r.get("request_Accept-Language") or "",
                   (r.get("RequestHost") or "").lower().replace("www.", ""))


def classify(s):
    """Return 'human', 'crawler' or None (drop) for a raw session dict."""
    pages = s["pages"]
    if not pages:
        return None
    if s["scan"] > 0:
        return "crawler"
    if s["assets"] == 0 and s["api"] == 0:
        return "crawler"  # a browser loads assets; a fetcher with a browser UA does not
    distinct = {p for p, _, _ in pages}
    interacted = s["tool_api"] > 0 or any(rx.match(p) and name in ("signup", "login", "checkout", "in-app", "demo") for p in distinct for rx, name in EVENTS)
    if s.get("hosting") and not interacted:
        # traffic from a hosting/cloud ASN with no interaction: monitors, AI fetchers, scrapers
        # (AWS Ashburn "/ > /en > /" in 6 s, GCP Pixel 6 walking every locale). Exception: iCloud
        # Private Relay puts real Safari users behind Cloudflare/Akamai/Fastly addresses.
        if not (PRIVATE_RELAY_RE.search(s.get("asn_name", "")) and re.search(r"iPhone|iPad|Macintosh", s["ua"]) and "Safari" in s["ua"] and "Chrome" not in s["ua"]):
            return "crawler"
    # a "visit" made only of 404 pages (guessing /account, /admin, /internal...) is a probe, not a reader
    if len(pages) >= 2 and all(st == 404 for _, _, st in pages):
        return "crawler"
    dur = (dt.datetime.fromisoformat(s["last"]) - dt.datetime.fromisoformat(s["first"])).total_seconds()
    if len(pages) >= 2 * len(distinct) and len(pages) >= 4 and dur < 20:
        return "crawler"  # the same one or two pages requested again and again inside seconds
    if len(distinct & LEGAL_SET) >= 3:
        return "crawler"
    roots = {p for p in distinct if LOCALE_RE.match(p) and p.count("/") == 1}
    if len(roots) >= 4:
        return "crawler"
    # many distinct pages inside one minute = a walk, not a read
    times = sorted((dt.datetime.fromisoformat(t), p) for p, t, _ in pages)
    for i in range(len(times)):
        window = {p for t, p in times[i:] if t - times[i][0] <= dt.timedelta(seconds=60)}
        if len(window) >= 5:
            return "crawler"
    return "human"


def build_day(day, rows, reader, nets, asn):
    """rows: list of tuples of that day -> {"sites": {sid: {"human": [...], "crawlers": n, "dropped": n}}}"""
    raw = {}  # (site, ip, ua) -> list of sessions (dicts)
    for (_, site, ip, ua, ts, path, status, ref, lang, host) in sorted(rows, key=lambda r: r[4]):
        try:
            if any(ipaddress.ip_address(ip) in n for n in nets):
                continue
        except ValueError:
            pass
        if BOT_RE.search(ua):
            continue
        t = dt.datetime.fromisoformat(ts)
        key = (site, ip, ua)
        lst = raw.setdefault(key, [])
        if not lst or t - dt.datetime.fromisoformat(lst[-1]["last"]) > GAP:
            asn_id, asn_name = asn.lookup(ip)
            lst.append({"site": site, "host": host, "ip": ip, "ua": ua, "first": ts, "last": ts, "pages": [], "assets": 0, "api": 0,
                        "tool_api": 0, "scan": 0, "errors": collections.Counter(), "ref": "", "lang": lang[:5],
                        "asn": asn_id, "asn_name": asn_name, "hosting": bool(HOSTING_RE.search(asn_name))})
        s = lst[-1]
        s["last"] = ts
        p = path.split("?")[0]
        if status >= 400:
            s["errors"][status] += 1
        if SCAN_RE.search(path):
            s["scan"] += 1
            continue
        if not s["ref"] and ref:
            src = source_of(ref, host)
            if src:
                s["ref"] = src
        if API_RE.match(p):
            s["api"] += 1
            if TOOL_API_RE.match(p):
                s["tool_api"] += 1
            continue
        if ASSET_RE.search(p):
            s["assets"] += 1
            continue
        s["pages"].append((p[:80], ts, status))
    out = {}
    for (site, ip, ua), lst in raw.items():
        site_out = out.setdefault(site, {"human": [], "crawlers": 0, "dropped": 0})
        for s in lst:
            kind = classify(s)
            if kind is None:
                site_out["dropped"] += 1
                continue
            if kind == "crawler":
                site_out["crawlers"] += 1
                continue
            seq = []
            for p, _, st in s["pages"]:
                if not seq or seq[-1] != p:
                    seq.append(p)
            events = []
            for p in seq:
                for rx, name in EVENTS:
                    if rx.match(p):
                        if name not in events:
                            events.append(name)
                        break
            if s["tool_api"]:
                events.append("tool-used")
            try:
                g = reader.get(ip) or {}
                country = g.get("country", {}).get("iso_code", "")
                city = g.get("city", {}).get("names", {}).get("en", "")
            except Exception:
                country, city = "", ""
            dev, os_ = device_of(ua)
            dur = int((dt.datetime.fromisoformat(s["last"]) - dt.datetime.fromisoformat(s["first"])).total_seconds())
            site_out["human"].append({
                "id": ip_hash(ip + ua), "t": s["first"][11:16], "end": s["last"][11:16], "dur": dur,
                "country": country, "city": city, "device": dev, "os": os_, "lang": s["lang"], "asn": s["asn_name"][:40],
                "source": s["ref"], "pages": seq[:40], "n": len(seq), "api": s["api"], "tool": s["tool_api"],
                "errors": {str(k): v for k, v in s["errors"].items()}, "events": events,
            })
        site_out["human"].sort(key=lambda x: x["t"])
    return out


def inventoria_inapp(day):
    """New users + activity by workspace for that day, from the InventorIA Postgres container."""
    try:
        cid = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=20).stdout.split()
        c = next((x for x in cid if x.startswith("mtxmywuo9yyda14n49p44jee")), None)
        if not c:
            return {}
        q = f"""
select json_build_object(
 'new_users', (select coalesce(json_agg(json_build_object('t', to_char(created_at, 'HH24:MI'), 'email', regexp_replace(email, '^(.).*@', '\\1***@'), 'use_case', primary_use_case, 'heard', hear_about_us) order by created_at), '[]'::json)
   from users where created_at::date = '{day}' and email not ilike '%e2e%' and email <> 'demo@inventoria-app.com'),
 'activity', (select coalesce(json_agg(json_build_object('company', c.name, 'events', n, 'first', f, 'last', l, 'actions', acts) order by n desc), '[]'::json)
   from (select a.company_id, count(*) n, to_char(min(a.timestamp), 'HH24:MI') f, to_char(max(a.timestamp), 'HH24:MI') l, string_agg(distinct a.action, ', ') acts
         from activity_logs a where a.timestamp::date = '{day}' group by a.company_id) x join companies c on c.id = x.company_id
   where c.name not ilike '%e2e%' and c.name not ilike '%(demo)%')
)"""
        r = subprocess.run(["docker", "exec", "-i", c, "psql", "-U", "invetoria", "-d", "invetoria", "-tA"], input=q, capture_output=True, text=True, timeout=30)
        return json.loads(r.stdout.strip() or "{}")
    except Exception as e:  # never break the site side because of the app side
        return {"error": str(e)[:120]}


def text_summary(day, doc):
    names = {sid: name for _, sid, name in SITES}
    lines = [f"PARCOURS HUMAINS — {day} (sessions page+asset, bots et crawlers écartés par leur motif de visite)"]
    sites = doc.get("sites", {})
    tot = sum(len(v["human"]) for v in sites.values())
    crawl = sum(v["crawlers"] for v in sites.values())
    lines.append(f"  {tot} sessions humaines, {crawl} crawlers déguisés écartés")
    for sid, v in sorted(sites.items(), key=lambda kv: -len(kv[1]["human"])):
        hs = v["human"]
        if not hs:
            continue
        ev = collections.Counter(e for h in hs for e in h["events"])
        src = collections.Counter(h["source"] for h in hs if h["source"])
        ctry = collections.Counter(h["country"] or "?" for h in hs)
        lines.append(f"  {names.get(sid, sid)}: {len(hs)} sessions — pays {', '.join(f'{c} {n}' for c, n in ctry.most_common(4))}"
                     + (f" — sources {', '.join(f'{s} {n}' for s, n in src.most_common(3))}" if src else "")
                     + (f" — événements {', '.join(f'{e} {n}' for e, n in ev.most_common(5))}" if ev else ""))
        for h in sorted(hs, key=lambda h: (-len(h["events"]), -h["n"]))[:5]:
            path = " > ".join(h["pages"][:6]) + (f" … +{h['n'] - 6}" if h["n"] > 6 else "")
            flags = (" [" + ", ".join(h["events"]) + "]") if h["events"] else ""
            err = (" erreurs " + ", ".join(f"{k}×{v}" for k, v in h["errors"].items())) if h["errors"] else ""
            lines.append(f"     {h['t']} {h['country']} {h['city']} {h['device']}/{h['os']} {h['dur']}s" + (f" via {h['source']}" if h["source"] else "") + f": {path}{flags}{err}")
    ia = doc.get("inapp", {}).get("inventoria", {})
    if ia:
        nu = ia.get("new_users") or []
        act = ia.get("activity") or []
        lines.append(f"  InventorIA dans l'app: {len(nu)} inscription(s)" + (": " + ", ".join(f"{u['t']} {u['email']}" for u in nu) if nu else "")
                     + f"; {len(act)} espace(s) actif(s)" + ("; " + "; ".join(f"{a['company']} {a['events']} actions ({a['actions']})" for a in act[:5]) if act else ""))
    return "\n".join(lines)


def post(doc, c):
    if not c.get("GLOBE_URL"):
        return "no GLOBE_URL"
    url = c["GLOBE_URL"].rstrip("/") + "/ingest-journeys"
    auth = base64.b64encode(f"{c.get('GLOBE_USER', '')}:{c.get('GLOBE_PASSWORD', '')}".encode()).decode()
    body = json.dumps(doc, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read(200).decode(errors="replace")


def main():
    args = sys.argv[1:]
    c = conf()
    nets = excluded_networks(c)
    reader = maxminddb.open_database(MMDB)
    asn = AsnTable(ASN_TSV)
    if not asn.rows:
        print("warning: no ASN table at", ASN_TSV, "(hosting traffic will not be filtered)", file=sys.stderr)
    os.makedirs(OUT, exist_ok=True)
    today = dt.datetime.now(dt.timezone.utc).date()
    if "--day" in args:
        days = [args[args.index("--day") + 1]]
    else:
        days = [(today - dt.timedelta(days=i)).isoformat() for i in range(DAYS)]
    wanted = set(days)
    by_day = collections.defaultdict(list)
    for row in read_rows(wanted):
        by_day[row[0]].append(row)
    docs = {}
    for day in days:
        if not by_day.get(day) and "--day" not in args:
            continue  # the log rotation keeps about two days; a day with no lines is unknown, not empty
        doc = {"day": day, "final": day != today.isoformat(), "sites": build_day(day, by_day.get(day, []), reader, nets, asn),
               "inapp": {"inventoria": inventoria_inapp(day)}}
        docs[day] = doc
        tmp = os.path.join(OUT, day + ".json.tmp")
        json.dump(doc, open(tmp, "w"), separators=(",", ":"))
        os.replace(tmp, os.path.join(OUT, day + ".json"))
    if "--text" in args:
        print(text_summary(days[0], docs[days[0]]))
        return 0
    if not docs:
        print("no log lines for the last", DAYS, "days", file=sys.stderr)
        return 1
    # all days on disk (older ones kept as they were), newest first
    alldays = {}
    for fn in sorted(glob.glob(os.path.join(OUT, "*.json")))[-30:]:
        try:
            d = json.load(open(fn))
            alldays[d["day"]] = d
        except Exception:
            pass
    web = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sites": {sid: name for _, sid, name in SITES}, "days": alldays}
    json.dump(web, open(os.path.join(STATE, "journeys-web.json"), "w"), separators=(",", ":"))
    h = sum(len(v["human"]) for d in alldays.values() for v in d["sites"].values())
    print(f"{web['generated']} {len(alldays)} days, {h} human sessions", file=sys.stderr)
    try:
        print("ingest-journeys:", post(web, c), file=sys.stderr)
    except Exception as e:
        print("ingest-journeys failed (kept locally):", e, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
