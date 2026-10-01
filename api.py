import asyncio
import json
import logging
import threading
import queue
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from kafka import KafkaConsumer, TopicPartition
from kafka.structs import OffsetAndMetadata
from rules.engine import evaluate_event
from alerts.manager import add_alert, get_alerts
from storage import (
    check_storage,
    close_storage,
    get_events,
    get_stored_alerts,
    initialize_storage,
    json_safe_value,
    persist_event,
)


app = FastAPI(title="Cap Scan SIEM API")
logger = logging.getLogger(__name__)
FRONTEND_DIR = Path(__file__).parent / "Frontend" / "client"
app.mount(
    "/dashboard-assets",
    StaticFiles(directory=FRONTEND_DIR),
    name="dashboard-assets",
)


# Allow local development frontends to connect.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:3002",
    "http://127.0.0.1:3002",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Every connected frontend gets its own queue
clients = []
clients_lock = threading.Lock()
worker_stop = threading.Event()
worker_thread = None
kafka_status_lock = threading.Lock()
kafka_status = {"connected": False, "error": None}
database_status_lock = threading.Lock()
database_connected = False
stats_lock = threading.Lock()
event_times = deque()
alert_counts = Counter()
source_alert_counts = Counter()
last_event_at = None


def set_kafka_status(connected, error=None):
    with kafka_status_lock:
        kafka_status["connected"] = connected
        kafka_status["error"] = error


def set_database_status(connected):
    global database_connected
    with database_status_lock:
        database_connected = connected


def record_event(event, detected_alerts):
    global last_event_at
    now = time.monotonic()
    with stats_lock:
        last_event_at = datetime.now(timezone.utc).isoformat()
        event_times.append(now)
        while event_times and now - event_times[0] > 60:
            event_times.popleft()
        for alert in detected_alerts:
            alert_counts[alert.get("rule_id", "UNKNOWN")] += 1
            source_ip = alert.get("src_ip")
            if source_ip:
                source_alert_counts[source_ip] += 1


def kafka_worker():
    while not worker_stop.is_set():
        consumer = None
        try:
            consumer = KafkaConsumer(
                "zeekdata-stream",
                bootstrap_servers="localhost:9092",
                auto_offset_reset="earliest",
                group_id="siem-frontend-stream",
                enable_auto_commit=False,
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
                bootstrap_timeout_ms=5000,
                request_timeout_ms=10000,
            )
            set_kafka_status(True)
            logger.info("Kafka consumer connected to zeekdata-stream")

            while not worker_stop.is_set():
                records = consumer.poll(timeout_ms=1000)
                for messages in records.values():
                    for message in messages:
                        event = message.value
                        if not isinstance(event, dict):
                            logger.warning("Ignoring non-object Kafka event")
                            continue

                        detected_alerts = evaluate_event(event)
                        try:
                            if not database_connected:
                                initialize_storage()
                            persist_event(event, detected_alerts)
                            topic_partition = TopicPartition(message.topic, message.partition)
                            consumer.commit({
                                topic_partition: OffsetAndMetadata(message.offset + 1, None)
                            })
                            set_database_status(True)
                        except Exception:
                            set_database_status(False)
                            logger.exception("Could not persist Kafka event; leaving offset uncommitted")
                            raise

                        record_event(event, detected_alerts)
                        for alert in detected_alerts:
                            logger.warning("ALERT: %s", alert)
                            add_alert(alert)

                        payload = {
                            "type": "log",
                            "event": event,
                            "alerts": detected_alerts,
                        }
                        with clients_lock:
                            current_clients = list(clients)
                        for client_queue in current_clients:
                            client_queue.put(payload)
        except Exception as error:
            set_kafka_status(False, str(error))
            logger.exception("Kafka consumer failed; retrying")
        finally:
            if consumer is not None:
                try:
                    consumer.close()
                except Exception:
                    logger.exception("Error while closing Kafka consumer")

        if not worker_stop.is_set():
            worker_stop.wait(3)

    set_kafka_status(False)


@app.on_event("startup")
def startup_event():
    global worker_thread
    worker_stop.clear()
    try:
        initialize_storage()
        set_database_status(True)
    except Exception:
        set_database_status(False)
        logger.exception("Database initialization failed; will retry on incoming events")
    worker_thread = threading.Thread(
        target=kafka_worker,
        name="kafka-consumer",
        daemon=True
    )
    worker_thread.start()


@app.on_event("shutdown")
def shutdown_event():
    worker_stop.set()
    if worker_thread is not None:
        worker_thread.join(timeout=3)
    close_storage()


@app.get("/dashboard", include_in_schema=False)
@app.get("/", include_in_schema=False)
def root():
    return FileResponse(FRONTEND_DIR / "vanilla.html")


@app.get("/api/health")
def health():
    with kafka_status_lock:
        status = dict(kafka_status)
    try:
        check_storage()
        set_database_status(True)
    except Exception:
        set_database_status(False)
    return {
        "api": "online",
        "kafka_connected": status["connected"],
        "kafka_error": status["error"],
        "database_connected": database_connected,
    }


@app.get("/api/summary")
def summary():
    now = time.monotonic()
    with stats_lock:
        while event_times and now - event_times[0] > 60:
            event_times.popleft()
        events_last_minute = len(event_times)
        buckets = [0] * 12
        for event_time in event_times:
            bucket = min(11, int((now - event_time) // 5))
            buckets[11 - bucket] += 1
        event_rate_series = [round(count / 5, 2) for count in buckets]
        total_alerts = sum(alert_counts.values())
        top_sources = [
            {"src_ip": source_ip, "count": count}
            for source_ip, count in source_alert_counts.most_common(4)
        ]
        rule_counts = dict(alert_counts)
        last_event_received = last_event_at
    with kafka_status_lock:
        connected = kafka_status["connected"]

    return json_safe_value({
        "kafka_connected": connected,
        "events_per_second": round(events_last_minute / 60, 2),
        "events_last_minute": events_last_minute,
        "alert_count": total_alerts,
        "top_alert_sources": top_sources,
        "alerts_by_rule": rule_counts,
        "event_rate_series": event_rate_series,
        "recent_alerts": get_alerts()[:3],
        "last_event_at": last_event_received,
    })


@app.get("/api/logs/stream")
async def log_stream(request: Request):

    client_queue = queue.Queue()

    with clients_lock:
        clients.append(client_queue)

    async def event_generator():
        last_heartbeat = time.monotonic()

        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    event = client_queue.get_nowait()
                    yield f"data: {json.dumps(json_safe_value(event), allow_nan=False)}\n\n"
                    last_heartbeat = time.monotonic()
                except queue.Empty:
                    if time.monotonic() - last_heartbeat >= 15:
                        yield ": keep-alive\n\n"
                        last_heartbeat = time.monotonic()
                    else:
                        await asyncio.sleep(0.1)

        finally:
            with clients_lock:
                if client_queue in clients:
                    clients.remove(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
        
    )
@app.get("/api/events")
def get_event_history(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    try:
        return {"events": get_events(limit=limit, offset=offset)}
    except Exception as error:
        logger.exception("Could not query event history")
        raise HTTPException(status_code=503, detail="Event history is unavailable") from error


@app.get("/api/alerts")
def get_alert_list(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    try:
        rows = get_stored_alerts(limit=limit, offset=offset)
        alerts = [
            {
                **row["payload"],
                "id": row["id"],
                "event_id": row["event_id"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return {"alerts": alerts}
    except Exception as error:
        logger.exception("Could not query alert history")
        raise HTTPException(status_code=503, detail="Alert history is unavailable") from error
