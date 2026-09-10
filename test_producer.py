from kafka import KafkaProducer
import json
import time

# connect to Kafka
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# send 5 test messages
for i in range(5):
    message = {"test_number": i, "text": "hello from Python"}
    producer.send('zeekdata-stream', message)
    print(f"Sent: {message}")
    time.sleep(1)

producer.flush()   # make sure everything is actually sent before the script ends
print("Done sending test messages.")
