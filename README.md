# Cap Scan

Cap Scan is an open-source mini SOC/SIEM that replays chronological Zeek connection records through Kafka, evaluates behavioral detections, persists events and alerts in PostgreSQL, and serves live updates to a lightweight HTML/CSS/JavaScript dashboard.

## Run locally

1. Install Docker Compose and Python 3.10 or newer.
2. Start Kafka, Zookeeper, and PostgreSQL:

   ```sh
   docker compose up -d
   ```

3. Install Python dependencies in your environment:

   ```sh
   python3 -m pip install -r requirements.txt
   ```

4. Start the API and dashboard:

   ```sh
   uvicorn api:app --host 0.0.0.0 --port 8000
   ```

5. Open <http://localhost:8000/>. Start replaying the dataset in a second terminal with `python3 stream_producer.py`.

The database URL defaults to `postgresql://sentinelstream:sentinelstream@localhost:5432/sentinelstream` and can be overridden with `DATABASE_URL`. Tables are created by the API at startup. The Docker volume `postgres_data` retains records between restarts.

## Dashboard and API

- `/` or `/dashboard`: static live dashboard, served by FastAPI from `Frontend/client/vanilla.html`.
- `/api/health`: API, Kafka, and PostgreSQL health.
- `/api/summary`: live-session traffic and alert counters.
- `/api/logs/stream`: Server-Sent Events for newly consumed events and detections.
- `/api/events?limit=100&offset=0`: paginated stored connection history.
- `/api/alerts?limit=100&offset=0`: paginated stored alert history, each linked to its source event by `event_id`.

The dashboard source is plain HTML, CSS, and JavaScript in `Frontend/client/vanilla.html`, `Frontend/client/dashboard-detail.css`, and `Frontend/client/dashboard-detail.js`. No frontend build step is required for the FastAPI-served dashboard.

## Behavioral rules

All detectors use Zeek connection telemetry and event timestamps, not the dataset's `tactic` or attack labels. Thresholds are in `rules/detections.py`.

1. `BRUTE_FORCE_001`: repeated failed or incomplete connections to authentication ports from one source to one destination service.
2. `PORT_SCAN_001`: many distinct destination ports contacted in a short time.
3. `EXFIL_001`: a large origin-byte transfer from a private source address to a public destination.
4. `DNS_BURST_001`: a burst of DNS connections from one source.
5. `UNUSUAL_PORT_001`: an uncommon, non-standard destination port after a minimum traffic baseline.
6. `LONG_CONNECTION_001`: a successful established connection lasting at least one hour.
7. `CONNECTION_FLOOD_001`: a source initiating a high number of connections in a short rolling window.
8. `PERIODIC_BEACON_001`: repeated successful connections to the same destination and port at regular intervals.

These are behavioral indicators for investigation, not proof that a host or connection is malicious. Validate and tune thresholds against the network and dataset being monitored.

## Checks

Run the focused detection tests with:

```sh
python3 -m unittest test_detections -v
```
