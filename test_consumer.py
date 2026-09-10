from kafka import KafkaConsumer
import json

# connect to Kafka and start reading from the beginning of the topic
consumer = KafkaConsumer(
    'zeekdata-stream',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',   # start from the very first message, not just new ones
    value_deserializer=lambda v: json.loads(v.decode('utf-8'))
)

print("Listening for messages... (press Ctrl+C to stop)")

for message in consumer:
    print(f"Received: {message.value}")
