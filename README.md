# Fleet Globe

Rotating globe of daily active users per app (GA4 Data API), one colour per app, day or 7-day view. Runs as one container: `server.py` serves `static/` behind basic auth and refreshes `static/data.json` every 6 hours via `pull.py`.

Env: `GLOBE_PASSWORD`, `GA_SA_JSON` (service-account key, JSON or base64), optional `GLOBE_USER`, `GLOBE_DAYS`, `GLOBE_REFRESH_HOURS`, `PORT`.
