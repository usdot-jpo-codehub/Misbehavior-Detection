import os
import json
from kafka import KafkaConsumer
from faulty_bsm_generator import FaultyBsmGenerator
from utils.asn.J2735 import DSRC
from utils.asn.Ieee1609Dot2 import IEEE1609dot2
IEEE_SPEC = IEEE1609dot2
DRSC_SPEC = DSRC

DRSC_SPEC.MessageFrame._SAFE_BND = False # disable boundary checks
DRSC_SPEC.MessageFrame._SAFE_VAL = False # disable boundary checks

DRSC_SPEC.AccelerationSet4Way._cont._dict['long']._SAFE_VAL = False
DRSC_SPEC.AccelerationSet4Way._cont._dict['long']._SAFE_BND = False
DRSC_SPEC.AccelerationSet4Way._cont._dict['long']._SAFE_BNDTAB = False
DRSC_SPEC.AccelerationSet4Way._cont._dict['long']._const_val.root[0].ub = 2010

IEEE_SPEC.Ieee1609Dot2Data._SAFE_BND = False # disable boundary checks
IEEE_SPEC.Ieee1609Dot2Data._SAFE_VAL = False # disable boundary checks


# --- Configuration ---
# Prefer DOCKER_HOST_IP if set, otherwise default to localhost
bootstrap = os.getenv("KAFKA_BOOTSTRAP")
if not bootstrap:
    host = os.getenv("DOCKER_HOST_IP", "localhost")
    bootstrap = f"{host}:9092"

topic ="topic.OdeRawEncodedBSMJson" #"topic.OdeBsmJson"#"topic.ProcessedBsm"

print(f"Connecting to Kafka at {bootstrap}, topic={topic}")
faulty_generator = FaultyBsmGenerator(IEEE_SPEC, DRSC_SPEC, 2025, "security", ("23A", 0))

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
        bsm_hex = bsm['payload']['data']['bytes'].encode('utf-8')
        faulty_generator.generate([bsm['payload']['data']['bytes'].encode('utf-8')], 
                              object_out="IeeeDot2Data", output_codec="jer")
        faulty_generator.write_bsms()
        print(bsm)
        # print("=" * 80)
        # print(f"Partition: {msg.partition}  Offset: {msg.offset}")

        # # Pretty-print full JSON
        # print(json.dumps(bsm, indent=2))

        # # Optionally pull out the coreData fields if present
        # payload = bsm.get("payload", {})
        # data = payload.get("data", {}) if isinstance(payload, dict) else {}
        # core = data.get("coreData", {}) if isinstance(data, dict) else {}

        # if core:
        #     veh_id = core.get("id")
        #     lat = core.get("lat")
        #     lon = core.get("long")
        #     speed = core.get("speed")
        #     print("\n[coreData]")
        #     print(f"  id={veh_id}  lat={lat}  lon={lon}  speed={speed}")

except KeyboardInterrupt:
    print("\nStopping consumer...")
finally:
    consumer.close()