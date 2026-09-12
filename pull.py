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


# The rule below (SANDBOX_IMPORTED_EVENTS) is unenforceable by comment alone, so it is a guard:
# no caller may ask the Data API for money. The device / city exclusion cannot rescue these rows
# either - measured 11/09/2026, StayFit's sandbox renewals carry deviceModel "iPhone17,3" in Paris
# (the TestFlight phone that made the purchase), not "arm64".
FORBIDDEN_METRICS = {"totalRevenue", "purchaseRevenue", "itemRevenue", "grossItemRevenue",
                     "averagePurchaseRevenue", "averagePurchaseRevenuePerUser",
                     "averageRevenuePerUser", "adRevenue", "grossPurchaseRevenue",
                     "totalPurchasers", "transactions"}


def _report(token, prop, body):
    bad = FORBIDDEN_METRICS & {m["name"] for m in body.get("metrics", [])}
    if bad:
        raise ValueError(f"GA4 revenue metric(s) {sorted(bad)} requested: GA4 revenue on these "
                         f"properties includes App Store SANDBOX renewals imported from ASC and "
                         f"is not earnings. Read the ASC sales report instead.")
    r = requests.post(f"https://analyticsdata.googleapis.com/v1beta/properties/{prop}:runReport",
                      headers={"Authorization": f"Bearer {token}"}, json=body, timeout=60)
    if r.status_code != 200:
        print(f"property {prop}: {r.status_code} {r.text[:200]}", file=sys.stderr)
        return None
    return r.json().get("rows", [])


DIMS = [{"name": "date"}, {"name": "countryId"}, {"name": "country"}, {"name": "city"}, {"name": "platform"},
        {"name": "deviceModel"}, {"name": "operatingSystemVersion"}]

# Test traffic that GA4 counts as real users (measured on StayFit, 02/09/2026: 137 "new users" for an
# app that was never on the App Store): iOS Simulator runs report deviceModel "arm64", and Apple's
# App Review devices sit in the towns around Cupertino. Both are dropped before anything is counted.
SIMULATOR_MODELS = {"arm64", "x86_64", "iPhone99,7"}
# Android emulators (our NRT runs on release builds) report deviceModel "sdk_gphone64_arm64",
# "sdk_gphone_arm64", "Android SDK built for x86", "emulator64_arm64"... (measured 08/09/2026).
EMULATOR_PREFIXES = ("sdk_gphone", "sdk_phone", "Android SDK built for", "emulator", "generic_x86", "AOSP on")
APPLE_REVIEW_CITIES = {"Cupertino", "Saratoga", "San Jose", "Santa Clara", "Sunnyvale", "Los Gatos", "Campbell"}
# Google Play's crawler (measured 12/09/2026 on every Android property, 7 to 15 "new users" per app
# in a week): deviceModel "OnePlus8Pro" on Android 11 with country "(not set)", the same device that
# produced the addViewInner crashes. It is not a user. Two rules, both counted and printed:
# the model + OS version pair (whatever the country: the same farm also geolocates to Brazil,
# Portugal, Indonesia, Ukraine) and any Android row with no country at all.
CRAWLER_DEVICES = {("OnePlus8Pro", "11")}          # (deviceModel, operatingSystemVersion)
# GA4 spells a missing country "(not set)"; an EMPTY string is a caller that did not query the
# country at all (unknown, not crawler), so it is deliberately absent here.
CRAWLER_COUNTRIES = {"(not set)", "(not_set)"}
# The apps set an `env` user property since 11/09/2026. Measured values, iOS: "store" (a real App
# Store install on a physical device - the ONLY one that collects at all now), "testflight",
# "debug", "simulator", "store-forced" (a --qa-store gate run) and "tester-forced". Android:
# "emulator", "debug", "android-unpublished". Anything that is not "store" is one of our own runs.
# The property only reaches the Data API once it is registered as a user-scoped custom dimension in
# GA4 (customUser:env); until then callers pass nothing here and the model / city rule does the work.
ENV_REAL_USER = "store"
# GA4 answers "(not set)" for every row collected before the property shipped, and for any install
# that never sent it. That is "unknown", NOT "tester": treating it as test traffic would delete every
# real user we have. Only an explicit value that is not "store" is one of ours.
ENV_UNKNOWN = {"", "(not set)", "(not_set)", "(none)"}

# Money is NEVER read from GA4. The App Store Connect link imports SANDBOX purchases as real revenue:
# measured on StayFit 11/09/2026, 7 app_store_subscription_renew events carried 587.93 of "revenue"
# while Apple's own sales report showed 0.00 developer proceeds since the 07/09 launch. Any future
# revenue metric added to this file must drop these event names first, and the only number we are
# allowed to call earnings is the "Developer Proceeds" column of the ASC SALES report.
SANDBOX_IMPORTED_EVENTS = {"app_store_subscription_renew", "app_store_subscription_convert",
                           "app_store_refund", "in_app_purchase"}


def _os_number(os_version):
    """GA4 answers operatingSystemVersion as "11" and operatingSystemWithVersion as "Android 11"."""
    v = (os_version or "").strip()
    for prefix in ("Android ", "iOS "):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v


def is_crawler_traffic(platform, model, os_version="", country=""):
    """True for Google Play's crawler: the OnePlus8Pro / Android 11 farm, or an Android row that
    carries no country. Only Android: an iOS row never comes from Play."""
    if platform != "Android":
        return False
    if os_version and (model, _os_number(os_version)) in CRAWLER_DEVICES:
        return True
    return (country or "").strip() in CRAWLER_COUNTRIES


def is_test_traffic(platform, city, model, env="", os_version="", country=""):
    """True when the row is one of our own runs (or a store crawler) rather than a real user.

    `env` is the app's own user property when the caller has it (GA4 customUser:env): an empty
    string means "not measured", and the device / city rule decides alone. `os_version` and
    `country` feed the Play-crawler rule (is_crawler_traffic); callers that do not query them pass
    nothing and only the emulator / simulator / Apple-review rules apply.
    """
    if env not in ENV_UNKNOWN and env != ENV_REAL_USER:
        return True
    if model in SIMULATOR_MODELS or model.startswith(EMULATOR_PREFIXES):
        return True
    if is_crawler_traffic(platform, model, os_version, country):
        return True
    return platform == "iOS" and city in APPLE_REVIEW_CITIES


def is_sandbox_revenue_event(event_name):
    """True for the App Store Connect imported purchase events, which are sandbox money."""
    return event_name in SANDBOX_IMPORTED_EVENTS


def run_report(token, prop, start, end, excluded=None):
    """Rows keyed by (date, cc, city, platform) with active users, new users and uninstalls.

    Uninstalls = count of GA4's automatically collected `app_remove` event, which Google only
    records on Android; iOS rows therefore always carry 0 there. `excluded`, when given, is a dict
    that receives the dropped rows per rule ("crawler", "test") so the caller can print them."""
    rows = {}
    excluded = excluded if excluded is not None else {}
    excluded.setdefault("crawler", 0)
    excluded.setdefault("crawler_new_users", 0)
    excluded.setdefault("test", 0)

    def drop(d, new_users=0):
        # crawler first so the two counters stay disjoint (the farm is not an emulator model)
        if is_crawler_traffic(d[4], d[5], d[6], d[2]):
            excluded["crawler"] += 1
            excluded["crawler_new_users"] += new_users
            return True
        if is_test_traffic(d[4], d[3], d[5]):
            excluded["test"] += 1
            return True
        return False

    users = _report(token, prop, {"dateRanges": [{"startDate": start, "endDate": end}], "dimensions": DIMS,
                                  "metrics": [{"name": "activeUsers"}, {"name": "newUsers"}], "limit": 100000})
    if users is None:
        return []
    for row in users:
        d = [x["value"] for x in row["dimensionValues"]]
        m = [int(float(x["value"])) for x in row["metricValues"]]
        if drop(d, m[1]):
            continue
        rows[tuple(d)] = {"date": d[0], "cc": d[1], "country": d[2], "city": d[3], "platform": d[4],
                          "users": m[0], "new": m[1], "removed": 0}
    removed = _report(token, prop, {"dateRanges": [{"startDate": start, "endDate": end}], "dimensions": DIMS,
                                    "metrics": [{"name": "eventCount"}], "limit": 100000,
                                    "dimensionFilter": {"filter": {"fieldName": "eventName",
                                                                   "stringFilter": {"matchType": "EXACT", "value": "app_remove"}}}})
    for row in removed or []:
        d = [x["value"] for x in row["dimensionValues"]]
        if drop(d):
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
    crawler = {}
    for app_id, label, prop, colour in APPS:
        excluded = {}
        rows = run_report(token, prop, f"{DAYS}daysAgo", "yesterday", excluded)
        status[app_id] = len(rows)
        crawler[app_id] = excluded.get("crawler_new_users", 0)
        print(f"{label}: excluded: {excluded.get('crawler', 0)} crawler rows "
              f"({excluded.get('crawler_new_users', 0)} new users; OnePlus8Pro/Android 11 or country (not set)), "
              f"{excluded.get('test', 0)} emulator/simulator rows", file=sys.stderr)
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
            "excluded": "iOS Simulator runs, Android emulators, Apple App Review devices (Cupertino area) and Google Play's "
                        "crawler (OnePlus8Pro on Android 11, Android rows with no country) are not counted; "
                        "no revenue is read from GA4 (the App Store Connect link imports sandbox purchases as real money)",
            "rows_per_app": status, "crawler_new_users_per_app": crawler, "points": points}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    json.dump(data, open(tmp, "w"), separators=(",", ":"))
    os.replace(tmp, OUT)
    print(f"wrote {OUT}: {len(points)} points, rows per app {status}, "
          f"{len(missing)} city names fell back to country centroid", file=sys.stderr)


if __name__ == "__main__":
    main()
