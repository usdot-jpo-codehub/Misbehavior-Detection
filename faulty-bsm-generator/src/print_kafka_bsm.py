import os
import json
from kafka import KafkaConsumer

# --- Configuration ---
# Prefer DOCKER_HOST_IP if set, otherwise default to localhost
bootstrap = os.getenv("KAFKA_BOOTSTRAP")
if not bootstrap:
    host = os.getenv("DOCKER_HOST_IP", "localhost")
    bootstrap = f"{host}:9092"

topic ="topic.Asn1DecoderOutput"#"topic.OdeBsmJson"#"topic.ProcessedBsm"
#"topic.OdeBsmJson"  # default ODE BSM JSON topic

print(f"Connecting to Kafka at {bootstrap}, topic={topic}")

# Create the consumer
consumer = KafkaConsumer(
    topic,
    bootstrap_servers=[bootstrap],
    group_id="bsm-print-demo",
    # start at the end ("latest") or beginning ("earliest") of the topic
    auto_offset_reset="latest",
    enable_auto_commit=True,
    value_deserializer=lambda v: json.loads(v.decode("utf-8")),
)

print("Waiting for BSM messages... (Ctrl+C to stop)\n")

try:
    for msg in consumer:
        bsm = msg.value  # this is the decoded JSON ODE puts on topic.OdeBsmJson

        print("=" * 80)
        print(f"Partition: {msg.partition}  Offset: {msg.offset}")

        # Pretty-print full JSON
        print(json.dumps(bsm, indent=2))

        # Optionally pull out the coreData fields if present
        payload = bsm.get("payload", {})
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        core = data.get("coreData", {}) if isinstance(data, dict) else {}

        if core:
            veh_id = core.get("id")
            lat = core.get("lat")
            lon = core.get("long")
            speed = core.get("speed")
            print("\n[coreData]")
            print(f"  id={veh_id}  lat={lat}  lon={lon}  speed={speed}")

except KeyboardInterrupt:
    print("\nStopping consumer...")
finally:
    consumer.close()