import socket
import json
import os
import re

import argparse
from confluent_kafka import Consumer
from test_faultybsm import FaultyBsmGenerator

from utils.asn.J2735 import DSRC
from utils.asn.Ieee1609Dot2 import IEEE1609dot2
from utils.constants import DATA_DIR, INPUT_BSM_DIR
IEEE_SPEC = IEEE1609dot2
DRSC_SPEC = DSRC


BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "topic.OdeBsmJson")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "ode-dot2-json-reader")
print("BOOTSTRAP_SERVERS repr:", repr(BOOTSTRAP_SERVERS))


def send_perturbed_msg(msg, UDP_IP="127.0.0.1", UDP_PORT=46800):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"\nTrying UDP target IP: {UDP_IP}:{UDP_PORT}")
    try:
        sent = sock.sendto(msg, (UDP_IP, UDP_PORT))
        print(f"✓ Sent {sent} bytes successfully to {UDP_IP}")
        
        # Now check ODE logs immediately
        print("Check ODE logs now with: docker compose -f jpo-ode/docker-compose.yml logs --tail 20 ode")
    except Exception as e:
        print(f"✗ Error sending to {UDP_IP}: {e}")


def fix_jer(jer_string):
    data = json.loads(jer_string)

    def walk(obj):
        if isinstance(obj, dict):
            if len(obj) == 1 and next(iter(obj.values())) == "":
                return next(iter(obj))
            else: return {k: walk(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [walk(i) for i in obj]
        elif isinstance(obj, str) and re.fullmatch(r'-?\d+', obj):
            return int(obj)
        return obj

    fixed = walk(data)
    return json.dumps(fixed)

'''
main
--------------------------
(1) read from kafka topic 
(2) parse into recognizable json format and 
(3) pass into faulty-bsm generator
'''
def main(args):
    msg_record = dict()
    faulty_generator = FaultyBsmGenerator(IEEE_SPEC, DRSC_SPEC, args.seed, args.fault, args.bundle, args.validate)

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "group.id": GROUP_ID,
        "auto.offset.reset": "earliest",
    })

    consumer.subscribe([TOPIC])

    print(f"Connected to {BOOTSTRAP_SERVERS}")
    print(f"Subscribed to {TOPIC}")

    try:
        while True:
            msg = consumer.poll(1.0)

            if msg is None:
                print("No message yet...")
                continue

            if msg.error():
                print(f"Consumer error: {msg.error()}")
                continue

            raw_value = msg.value().decode("utf-8", errors="replace")

            print("\n" + "=" * 100)
            print(
                f"topic={msg.topic()} partition={msg.partition()} "
                f"offset={msg.offset()}"
            )

            try:
                print(f"Encountered message!")
                parsed = json.loads(raw_value)
                #print(json.dumps(parsed, indent=2))

                # clean the JER encoding for processing and decoding
                clean_ieeedot2data_msg = fix_jer(parsed['metadata']['ieee1609dot2DecodedJson'])
                # check the dictionary if we've already seen this message
                msg_hash = hash(bytes.fromhex(parsed['metadata']['asn1']))
                if msg_hash in msg_record: 
                    print(f"I made this message! Ignoring...")
                    continue

                faulty_generator.generate([clean_ieeedot2data_msg for _ in range(0, args.repeat_files)], input_codec='jer', output_codec='coer', object_out='IeeeDot2Data')
                msg_cache = faulty_generator.cache

                # hash the new messages so we redo it
                for item in msg_cache:
                    perturb_hash = hash(item.msg)
                    msg_record[perturb_hash] = item.msg
                    send_perturbed_msg(item.msg)

                # write to file and clear the cache 
                faulty_generator.write_bsms()
                faulty_generator.clear()

                print(f"Added fault to message (see /output/log.csv).")


            except json.JSONDecodeError:
                print(raw_value)

    except KeyboardInterrupt:
        print("\nStopping consumer...")
    finally:
        consumer.close()


if __name__ == '__main__': 
    # Get parameters
    parser = argparse.ArgumentParser(description ='Arguments for Faulty-BSM Generator')
    parser.add_argument('-o', '--output_codec',
                        type = str, default='COER',
                        help ='codec to encode file to (COER, PER, JER)')
    parser.add_argument('-c', '--repeat_files',
                        type = int, default=1,
                        help ='number of times to copy incoming file')
    parser.add_argument('-s', '--seed',
                        type = int, default=2026,
                        help ='numpy random seed for predictable randomness')
    parser.add_argument('-m', '--fault',
                        type = str, default="security",
                        help ='fault to apply to BSM')
    parser.add_argument('-v', '--validate',
                        type = bool, default=False,
                        help ='validate signed messages via SCMS (requires API_KEY env variable to be set)')
    parser.add_argument('-b', '--bundle',
                        type = str, default='eebb92918c25d907',
                        help ='bundle digest (for load from bundle path)')

    
    args = parser.parse_args()
    main(args)