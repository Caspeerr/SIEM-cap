import pandas as pd
from kafka import KafkaProducer
from kafka.errors import KafkaError
import json
import time

# ============================================
# STEP 1: Connect to Kafka
# ============================================
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    key_serializer=lambda k: k.encode('utf-8') if k else None,
    acks='all',       # wait for the broker to fully acknowledge each message
    retries=5,         # retry transient send failures instead of dropping them
    linger_ms=5        # small batching window, negligible for our delay sizes
)

# ============================================
# STEP 2: Load the dataset and sort by real event time
# ============================================
# NOTE: the raw file is NOT already in time order (checked directly -
# roughly a quarter of consecutive rows are out of sequence), so a
# one-time full sort is required to replay events in the order they
# actually happened.
print("Loading dataset... this may take a moment")
df = pd.read_csv("logs/combined_zeekdata.csv")
print(f"Loaded {len(df):,} total rows")

df = df.sort_values("ts").reset_index(drop=True)

# ============================================
# STEP 3: Slice out one contiguous window instead of random-sampling
# ============================================
# A random, tactic-balanced sample destroys ordering AND makes attacks
# look artificially common. A contiguous slice preserves both the real
# sequence of events and the real (mostly-benign) class balance.
WINDOW_SIZE = 2000000     # number of consecutive events to replay
WINDOW_START = 0       # row index to start the slice at - adjust to land on
                        # a window that includes some attack tactics if you want

window = df.iloc[WINDOW_START:WINDOW_START + WINDOW_SIZE].reset_index(drop=True)
print(f"Replaying a contiguous window of {len(window):,} rows")
print(window["tactic"].value_counts())

# ============================================
# STEP 4: Compute real inter-event gaps, scaled for demo speed
# ============================================
SPEED_MULTIPLIER = 100   # e.g. 100x means a real 10s gap becomes 0.1s
MAX_DELAY_SECONDS = 2.0  # cap so a real multi-hour gap doesn't stall the demo

deltas = window["ts"].diff().fillna(0)          # real gap before each row
scaled_delays = (deltas / SPEED_MULTIPLIER).clip(lower=0, upper=MAX_DELAY_SECONDS)

# ============================================
# STEP 5: Stream each row into Kafka, preserving order and real spacing
# ============================================
sent, failed = 0, 0

for i, row in window.iterrows():
    delay = scaled_delays.iloc[i]
    if delay > 0:
        time.sleep(delay)

    event = row.to_dict()
    key = str(event.get("src_ip", ""))  # key by src_ip so a flow lands on one partition

    try:
        producer.send('zeekdata-stream', key=key, value=event)
        sent += 1
    except KafkaError as e:
        failed += 1
        print(f"[!] Failed to send row {i}: {e}")
        continue

    print(f"[{i+1}/{len(window)}] delay={delay:.3f}s tactic={event.get('tactic')} src_ip={key}")

producer.flush()
print(f"Finished replaying window. sent={sent} failed={failed}")
