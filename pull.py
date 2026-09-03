#!/usr/bin/env python3
"""Pull daily active users per city for every app from the GA4 Data API and write data.json.

Auth: a read-only service account (Firebase Viewer on each project), key passed as the
GA_SA_JSON env var (raw JSON or base64) or as a file path in GA_SA_FILE.
Geocoding: GeoNames cities15000 (free) for city dots, a country-centroid fallback otherwise.
"""
import base64, csv, io, json, os, sys, time, zipfile, urllib.request
import jwt, requests

APPS = [
    # id, label, GA4 property id, colour. Order and colours are fixed (legend + chart adjacency
    # validated for colour-vision deficiency on the dark surface, dataviz palette, 02/09/2026).
    ("maze",    "Maze Glass",   "537950677", "#3987e5"),
    ("forge",   "Forge",        "541285886", "#d95926"),
    ("bloom",   "Bloom",        "537653605", "#199e70"),
    ("trivio",  "Trivio",       "540459488", "#c98500"),
    ("nine",    "Nine",         "551676033", "#d55181"),
    ("astral",  "Astral",       "552700468", "#9085e9"),   # re-linked 03/09/2026 (old property 541399507 unreachable)
    ("stayfit", "StayFit",      "547686026", "#e66767"),
    ("puzzle",  "Puzzle Glass", "552735224", "#008300"),   # Analytics enabled 03/09/2026
]
DAYS = int(os.environ.get("GLOBE_DAYS", "90"))
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("GLOBE_DATA", os.path.join(HERE, "static", "data.json"))
CITIES_TXT = os.environ.get("GLOBE_CITIES", os.path.join(HERE, "cities15000.txt"))


def sa_token():
    raw = os.environ.get("GA_SA_JSON")
    if raw:
        try:
            key = json.loads(raw)
        except ValueError:
            key = json.loads(base64.b64decode(raw))
    else:
        key = json.load(open(os.environ.get("GA_SA_FILE", os.path.expanduser("~/Claude/infra/ga4/globe-reader.json"))))
    now = int(time.time())
    assertion = jwt.encode({"iss": key["client_email"], "scope": "https://www.googleapis.com/auth/analytics.readonly",
                            "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600},
                           key["private_key"], algorithm="RS256")
    r = requests.post("https://oauth2.googleapis.com/token",
                      data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def ensure_cities():
    if os.path.exists(CITIES_TXT):
        return
    url = "https://download.geonames.org/export/dump/cities15000.zip"
    print("downloading", url, file=sys.stderr)
    data = urllib.request.urlopen(url, timeout=120).read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        open(CITIES_TXT, "wb").write(z.read("cities15000.txt"))


def load_cities():
    """(country_code, lowercase name) -> (lat, lng); alternate names included; biggest city wins."""
    ensure_cities()
    best = {}
    centroid_acc = {}
    with open(CITIES_TXT, encoding="utf-8") as f:
        for row in csv.reader(f, delimiter="\t", quoting=csv.QUOTE_NONE):
            name, ascii_name, alts, lat, lng, cc, pop = row[1], row[2], row[3], float(row[4]), float(row[5]), row[8], int(row[14] or 0)
            names = {name.lower(), ascii_name.lower()} | {a.lower() for a in alts.split(",") if a}
            for n in names:
                k = (cc, n)
                if k not in best or best[k][2] < pop:
                    best[k] = (lat, lng, pop)
            acc = centroid_acc.setdefault(cc, [0.0, 0.0, 0])
            acc[0] += lat * max(pop, 1); acc[1] += lng * max(pop, 1); acc[2] += max(pop, 1)
    centroids = {cc: (a[0] / a[2], a[1] / a[2]) for cc, a in centroid_acc.items() if a[2]}
    return best, centroids


def _report(token, prop, body):
    r = requests.post(f"https://analyticsdata.googleapis.com/v1beta/properties/{prop}:runReport",
                      headers={"Authorization": f"Bearer {token}"}, json=body, timeout=60)
    if r.status_code != 200:
        print(f"property {prop}: {r.status_code} {r.text[:200]}", file=sys.stderr)
        return None
    return r.json().get("rows", [])


DIMS = [{"name": "date"}, {"name": "countryId"}, {"name": "country"}, {"name": "city"}, {"name": "platform"}, {"name": "deviceModel"}]

# Test traffic that GA4 counts as real users (measured on StayFit, 02/09/2026: 137 "new users" for an
# app that was never on the App Store): iOS Simulator runs report deviceModel "arm64", and Apple's
# App Review devices sit in the towns around Cupertino. Both are dropped before anything is counted.
SIMULATOR_MODELS = {"arm64", "x86_64", "iPhone99,7"}
APPLE_REVIEW_CITIES = {"Cupertino", "Saratoga", "San Jose", "Santa Clara", "Sunnyvale", "Los Gatos", "Campbell"}


def is_test_traffic(platform, city, model):
    if model in SIMULATOR_MODELS:
        return True
    return platform == "iOS" and city in APPLE_REVIEW_CITIES


def run_report(token, prop, start, end):
    """Rows keyed by (date, cc, city, platform) with active users, new users and uninstalls.

    Uninstalls = count of GA4's automatically collected `app_remove` event, which Google only
    records on Android; iOS rows therefore always carry 0 there."""
    rows = {}
    users = _report(token, prop, {"dateRanges": [{"startDate": start, "endDate": end}], "dimensions": DIMS,
                                  "metrics": [{"name": "activeUsers"}, {"name": "newUsers"}], "limit": 100000})
    if users is None:
        return []
    for row in users:
        d = [x["value"] for x in row["dimensionValues"]]
        m = [int(float(x["value"])) for x in row["metricValues"]]
        if is_test_traffic(d[4], d[3], d[5]):
            continue
        rows[tuple(d)] = {"date": d[0], "cc": d[1], "country": d[2], "city": d[3], "platform": d[4],
                          "users": m[0], "new": m[1], "removed": 0}
    removed = _report(token, prop, {"dateRanges": [{"startDate": start, "endDate": end}], "dimensions": DIMS,
                                    "metrics": [{"name": "eventCount"}], "limit": 100000,
                                    "dimensionFilter": {"filter": {"fieldName": "eventName",
                                                                   "stringFilter": {"matchType": "EXACT", "value": "app_remove"}}}})
    for row in removed or []:
        d = [x["value"] for x in row["dimensionValues"]]
        if is_test_traffic(d[4], d[3], d[5]):
            continue
        n = int(float(row["metricValues"][0]["value"]))
        rows.setdefault(tuple(d), {"date": d[0], "cc": d[1], "country": d[2], "city": d[3], "platform": d[4],
                                   "users": 0, "new": 0, "removed": 0})["removed"] += n
    merged = {}
    for k, v in rows.items():
        mk = k[:5]
        if mk in merged:
            for f in ("users", "new", "removed"):
                merged[mk][f] += v[f]
        else:
            merged[mk] = dict(v)
    return list(merged.values())


def main():
    token = sa_token()
    cities, centroids = load_cities()
    points, missing = [], {}
    status = {}
    for app_id, label, prop, colour in APPS:
        rows = run_report(token, prop, f"{DAYS}daysAgo", "yesterday")
        status[app_id] = len(rows)
        for r in rows:
            cc, city = r["cc"], r["city"]
            hit = cities.get((cc, city.lower())) if city and city != "(not set)" else None
            if hit:
                lat, lng, exact = hit[0], hit[1], True
            elif cc in centroids:
                lat, lng, exact = centroids[cc][0], centroids[cc][1], False
                missing[(cc, city)] = missing.get((cc, city), 0) + 1
            else:
                continue
            points.append({"a": app_id, "d": r["date"], "lat": round(lat, 3), "lng": round(lng, 3),
                           "city": city if exact else "", "cc": cc, "country": r["country"],
                           "p": r["platform"], "u": r["users"], "n": r["new"], "r": r["removed"]})
    data = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "days": DAYS,
            "apps": [{"id": a, "name": n, "color": c} for a, n, _, c in APPS],
            "metrics": {"u": "Active users", "n": "First-time users", "r": "Uninstalls (Android only)"},
            "excluded": "iOS Simulator runs and Apple App Review devices (Cupertino area) are not counted",
            "rows_per_app": status, "points": points}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    json.dump(data, open(tmp, "w"), separators=(",", ":"))
    os.replace(tmp, OUT)
    print(f"wrote {OUT}: {len(points)} points, rows per app {status}, "
          f"{len(missing)} city names fell back to country centroid", file=sys.stderr)


if __name__ == "__main__":
    main()
