import asyncio
import json
import threading
import queue

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from kafka import KafkaConsumer
from rules.engine import evaluate_event
from alerts.manager import add_alert, get_alerts


app = FastAPI(title="SIEM Streaming API")


# Allow the React/Vite frontend to connect
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


def kafka_worker():
    consumer = KafkaConsumer(
        "zeekdata-stream",
        bootstrap_servers="localhost:9092",

        # Important:
        # Only receive events that arrive after this consumer starts.
        auto_offset_reset="latest",

        # Unique consumer group so the API gets its own stream.
        group_id="siem-frontend-stream",

        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    print("Kafka consumer started...")
    print("Listening to zeekdata-stream")

    for message in consumer:
        event = message.value

        print("Received:", event)

        # --------------------------------
        # RUN SECURITY RULES
        # --------------------------------

        detected_alerts = evaluate_event(event)

        # --------------------------------
        # STORE AND BROADCAST ALERTS
        # --------------------------------

        for alert in detected_alerts:
            print("ALERT:", alert)

            add_alert(alert)

        # --------------------------------
        # SEND ORIGINAL LOG TO FRONTEND
        # --------------------------------

        with clients_lock:
            current_clients = list(clients)

        for client_queue in current_clients:
            client_queue.put({
                "type": "log",
                "event": event,
                "alerts": detected_alerts,
            })


@app.on_event("startup")
def startup_event():
    thread = threading.Thread(
        target=kafka_worker,
        daemon=True
    )

    thread.start()


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "SIEM Streaming API"
    }


@app.get("/api/logs/stream")
async def log_stream():

    client_queue = queue.Queue()

    with clients_lock:
        clients.append(client_queue)

    async def event_generator():

        try:
            while True:

                # Don't block the async event loop.
                try:
                    event = client_queue.get_nowait()

                    yield f"data: {json.dumps(event)}\n\n"

                except queue.Empty:
                    await asyncio.sleep(0.05)

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
@app.get("/api/alerts")
def get_alert_list():
    return {
        "alerts": get_alerts()
    }
