# Endpoint Monitoring

The Endpoint Monitoring page provides a lightweight, authenticated endpoint inventory. It is intentionally not an EDR: the application does not install an endpoint agent, kernel driver, packet capture, telemetry collector, or malware execution component.

## Demo records

Registering an endpoint through `POST /api/endpoints` creates a user-owned endpoint record and three deterministic events marked `demoData: true`. The events demonstrate a normal system event, a medium suspicious authentication signal, and a high suspicious process-activity signal. They do not describe, collect, or execute anything on the submitted device.

Every endpoint and event returned by this module is labeled demo data. `lastSeenAt` records registration time; it is not a heartbeat or an indication of real-time connectivity.

## API

- `POST /api/endpoints` registers `{hostname, deviceName, operatingSystem, platform, status?}`. Hostnames are unique per user and status is `ONLINE`, `OFFLINE`, or `UNKNOWN`.
- `GET /api/endpoints` lists the signed-in user's endpoint records with device/status/last-seen fields and derived risk summaries.
- `GET /api/endpoints/{id}` returns one owned endpoint and its events. `suspiciousOnly=true` filters the returned event list while keeping the summary based on all stored events.
- `GET /api/endpoints/{id}/events` returns the owned endpoint's basic events, with the same optional `suspiciousOnly` filter.

Missing endpoints and other users' endpoints return 404. All endpoints require the existing bearer authentication.

## Risk summary

The score is a capped sum of suspicious demo-event severities: LOW +5, MEDIUM +15, HIGH +30, and CRITICAL +50. Risk levels are LOW (0–25), MEDIUM (26–50), HIGH (51–75), and CRITICAL (76–100). This is a transparent demo summary, not a device-security verdict.

Migration V13 creates the endpoint and endpoint event tables. Validate with `mvn test` in `backend`, plus `npm test` and `npm run build` in `frontend`.
