import argparse
import ctypes
import glob
import hashlib
import json
import os
import re
import sys

import encoder_utils, decoder_utils
from asn1c_bridge import load_lib, get_td, RC_OK
from confluent_kafka import Consumer
from signing_utils import load_signing_key, select_pseudonym_cert, select_rsu_cert
from utils import OBS_TITLES

_cert_cache = {}

BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "topic.OdeBsmJson")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "misbehavior-detection")


def _compute_hashedid8(lib, cert_json_dict):
    """Return the HashedId8 hex string for a certificate: SHA-256(OER(cert))[-8:]."""
    cert_td = get_td(lib, "Certificate")
    cert_jer = json.dumps(cert_json_dict).encode()
    sptr, rval = decoder_utils.decode_jer(lib, cert_td, cert_jer)
    if rval.code != RC_OK:
        return None
    cert_oer = encoder_utils.encode_oer(lib, cert_td, sptr)
    return hashlib.sha256(cert_oer).digest()[-8:].hex().upper()


def _decode_bsm_bytes(data):
    """Decode raw OER bytes for an Ieee1609Dot2Data-wrapped BSM.

    Returns (ieee_dict, message_frame, data_hex).
    """
    lib = ctypes.CDLL("libs/J3287.so")
    td = get_td(lib, "Ieee1609Dot2Data")

    data_hex = data.hex()
    sptr, rval = decoder_utils.decode_oer(lib, td, data)
    # Debug
    #print(f"OER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"OER decode failed: code={rval.code} consumed={rval.consumed}")
    ieee_jer = encoder_utils.encode_jer(lib, td, sptr)
    ieee_dict = json.loads(ieee_jer)

    signer = ieee_dict.get("content", {}).get("signedData", {}).get("signer", {})
    if "certificate" in signer:
        cert_json = signer["certificate"][0]
        hashedid8 = _compute_hashedid8(lib, cert_json)
        if hashedid8:
            _cert_cache[hashedid8] = cert_json
    elif "digest" in signer:
        print("DIGEST: ", signer["digest"])
        digest_hex = signer["digest"].upper()
        if digest_hex in _cert_cache:
            ieee_dict["content"]["signedData"]["signer"] = {"certificate": [_cert_cache[digest_hex]]}
            ieee_jer_mod = json.dumps(ieee_dict).encode()
            sptr_mod, rval_mod = decoder_utils.decode_jer(lib, td, ieee_jer_mod)
            if rval_mod.code == RC_OK:
                data_hex = encoder_utils.encode_oer(lib, td, sptr_mod).hex()

    message_frame_hex = ieee_dict["content"]["signedData"]["tbsData"]["payload"]["data"]["content"]["unsecuredData"]
    message_frame = bytes.fromhex(message_frame_hex)

    lib = ctypes.CDLL("libs/J2735.so")
    td = get_td(lib, "MessageFrame")
    sptr, rval = decoder_utils.decode_uper(lib, td, message_frame)
    # Debug
    #print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed: code={rval.code} consumed={rval.consumed}")
    message_frame_jer = encoder_utils.encode_jer(lib, td, sptr)
    message_frame = json.loads(message_frame_jer)
    
    basicsafety_hex = message_frame.get("value", {})
    basicsafety = bytes.fromhex(basicsafety_hex)
    td = get_td(lib, "BasicSafetyMessage")
    sptr, rval = decoder_utils.decode_uper(lib, td, basicsafety)
    # Debug
    #print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed: code={rval.code} consumed={rval.consumed}")
    bsm_jer = encoder_utils.encode_jer(lib, td, sptr)
    bsm = json.loads(bsm_jer)
    bsm = {"BasicSafetyMessage": bsm}
    message_frame['value'] = bsm
    return ieee_dict, message_frame, data_hex


def load_BSM(filepath):
    """Load a BSM from a binary OER file on disk."""
    with open(filepath, "rb") as f:
        data = f.read()
    return _decode_bsm_bytes(data)


def fix_jer(jer_string):
    """Normalize ODE's JER encoding quirks.

    - Single-key dicts whose value is an empty string are collapsed to just the key.
    - Numeric strings are converted to ints.
    """
    data = json.loads(jer_string)

    def walk(obj):
        if isinstance(obj, dict):
            if len(obj) == 1 and next(iter(obj.values())) == "":
                return next(iter(obj))
            else:
                return {k: walk(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [walk(i) for i in obj]
        elif isinstance(obj, str) and re.fullmatch(r'-?\d+', obj):
            return int(obj)
        return obj

    return json.dumps(walk(data))


def _run_detections(ieee, bsm, ieee_hex, label,
                    observations, check_names, reports,
                    cert_bytes, signing_key, ma_key, debug):
    """Run all configured observations against a single BSM and append any new reports.

    Returns the number of new detections found.
    """
    print(f"\nRunning {len(observations)} misbehavior check(s):")
    n_detected = 0
    for observation in observations:
        obs_name = check_names.get(id(observation), type(observation).__name__)
        print(f"  [ ] {obs_name} ...", end="", flush=True)
        prior_count = len(observation.detections)
        detections = observation.analyze_bsm(ieee, bsm, ieee_hex)
        new_detections = detections[prior_count:]
        if new_detections:
            print(f"\r  [!] {obs_name}: DETECTED ({len(new_detections)} detection(s))")
            n_detected += len(new_detections)
        else:
            print(f"\r  [✓] {obs_name}: PASS")
        for detection in new_detections:
            target_id, observation_id, evidence = detection
            mbr = observation.generate_report(target_id, observation_id, evidence, cert_bytes, signing_key, ma_key)
            reports.append(mbr)
            if debug:
                observation.print_report()
                observation.debug_report()
            os.makedirs("output", exist_ok=True)
            coer_path = f"output/mbr-{observation.report_type}-{len(reports)}.coer"
            with open(coer_path, "wb") as f:
                f.write(mbr)
            print(f"      -> Wrote report: {coer_path}")
    print(f"\nSummary for {label}: {n_detected} misbehavior(s) detected.")
    return n_detected


def run_kafka(observations, check_names, reports, cert_bytes, signing_key, args):
    """Subscribe to topic.OdeBsmJson and run detection on each incoming BSM.

    The raw ASN.1 hex from ODE metadata is decoded with the same pipeline used
    for file-based BSMs.  Messages that fail to decode are skipped with a warning.
    Press Ctrl-C to stop.
    """
    bootstrap = getattr(args, 'kafka_bootstrap', None) or BOOTSTRAP_SERVERS
    topic    = getattr(args, 'kafka_topic',     None) or KAFKA_TOPIC
    group_id = getattr(args, 'kafka_group_id',  None) or KAFKA_GROUP_ID

    consumer = Consumer({
        "bootstrap.servers": bootstrap,
        "group.id":          group_id,
        "auto.offset.reset": "latest",
    })
    consumer.subscribe([topic])

    print(f"Kafka consumer connected to {bootstrap}")
    print(f"Subscribed to {topic} (group: {group_id})")
    print("Waiting for BSMs — press Ctrl-C to stop.\n")

    msg_count = 0
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print(f"[Kafka error] {msg.error()}", file=sys.stderr)
                continue

            raw = msg.value().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                print("[warn] Could not parse Kafka message as JSON — skipping.", file=sys.stderr)
                continue

            asn1_hex = parsed.get("metadata", {}).get("asn1")
            if not asn1_hex:
                print("[warn] Message has no metadata.asn1 field — skipping.", file=sys.stderr)
                continue

            msg_count += 1
            label = (
                f"kafka msg #{msg_count} "
                f"(topic={msg.topic()} partition={msg.partition()} offset={msg.offset()})"
            )
            print(f"\n{'=' * 80}")
            print(f"--- {label} ---")

            try:
                data = bytes.fromhex(asn1_hex)
                ieee, bsm, ieee_hex = _decode_bsm_bytes(data)
            except Exception as exc:
                print(f"[warn] Failed to decode BSM: {exc} — skipping.", file=sys.stderr)
                continue

            _run_detections(
                ieee, bsm, ieee_hex, label,
                observations, check_names, reports,
                cert_bytes, signing_key, args.ma_key, args.debug,
            )

    except KeyboardInterrupt:
        print("\nStopping Kafka consumer...")
    finally:
        consumer.close()

    print(f"\n=== Total reports generated: {len(reports)} ===")


def launch():
    parser = argparse.ArgumentParser(description='run misbehavior detection')
    parser.add_argument('-m', '--misbehaviors', type=str, nargs='+',
                        help='space-separated list of misbehaviors to check; '
                             'omit to run all available misbehaviors (default)',
                        default=None)
    parser.add_argument('-b', '--bsm', type=str,
                        help='path to a BSM .coer file OR a directory containing .coer files',
                        default=None)
    parser.add_argument('-c', "--certs-dir",
                        help="SCMS bundle directory. For RSU bundles (rsu-*/downloadFiles/ layout) "
                        "the currently valid cert is selected automatically. For pseudonym bundles "
                        "(download/{i}/{i}_{j}.cert layout with sgn_expnsn.key) butterfly expansion "
                        "is applied automatically. Detection is based on the presence of download/.",)
    parser.add_argument('--ma-key', type=str, default=None,
                        help='path to the MA recipient certificate file (e.g. certs/ma_public_key.cert)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='optional flag to output reports as JER')

    # Kafka options
    kafka_grp = parser.add_argument_group('Kafka live stream')
    kafka_grp.add_argument('--kafka', action='store_true',
                           help='subscribe to the ODE OdeBsmJson Kafka topic instead of reading files')
    kafka_grp.add_argument('--kafka-bootstrap', type=str, default=None,
                           help=f'Kafka bootstrap servers (default: $KAFKA_BOOTSTRAP or {BOOTSTRAP_SERVERS})')
    kafka_grp.add_argument('--kafka-topic', type=str, default=None,
                           help=f'Kafka topic to consume (default: $KAFKA_TOPIC or {KAFKA_TOPIC})')
    kafka_grp.add_argument('--kafka-group-id', type=str, default=None,
                           help=f'Kafka consumer group ID (default: $KAFKA_GROUP_ID or {KAFKA_GROUP_ID})')

    args = parser.parse_args()

    if not args.kafka and args.bsm is None:
        args.bsm = 'data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer'

    misbehavior_list = args.misbehaviors if args.misbehaviors is not None else list(OBS_TITLES.keys())
    observations = []
    for misbehavior_type in misbehavior_list:
        if misbehavior_type in OBS_TITLES:
            observations.append(OBS_TITLES[misbehavior_type])
        else:
            raise Exception(f"{misbehavior_type} not a valid observation name!")

    cert_bytes = None
    signing_key = None

    if args.certs_dir:
        if os.path.isdir(os.path.join(args.certs_dir, 'download')):
            # Pseudonym bundle: download/{i}/{i}_{j}.cert + sgn_expnsn.key
            print(f"  Detected pseudonym bundle: {args.certs_dir}", file=sys.stderr)
            cert_path, key_path = select_pseudonym_cert(args.certs_dir)
            signing_key = load_signing_key(key_path, bundle_dir=args.certs_dir)
        else:
            # RSU bundle: rsu-*/downloadFiles/*.cert
            cert_path, key_path = select_rsu_cert(args.certs_dir)
            signing_key = load_signing_key(key_path)
        with open(cert_path, 'rb') as fh:
            cert_bytes = fh.read()
        print(f"  Selected cert: {cert_path} "
              f"(SHA-256: {hashlib.sha256(cert_bytes).hexdigest()[:16]}...)",
              file=sys.stderr)

    reports = []
    check_names = {id(obs): name for name, obs in OBS_TITLES.items()}

    # ── Kafka live-stream mode ────────────────────────────────────────────────
    if args.kafka:
        run_kafka(observations, check_names, reports, cert_bytes, signing_key, args)
        return

    # ── File / directory mode ─────────────────────────────────────────────────
    bsm_input = args.bsm
    if os.path.isdir(bsm_input):
        bsm_paths = sorted([f for f in glob.glob(os.path.join(bsm_input, "*")) if os.path.isfile(f)])
        if not bsm_paths:
            raise SystemExit(f"No files found in directory: {bsm_input}")
        print(f"Found {len(bsm_paths)} files in directory: {bsm_input}")
    else:
        if not os.path.isfile(bsm_input):
            raise SystemExit(f"BSM path does not exist: {bsm_input}")
        bsm_paths = [bsm_input]

    for bsm_path in bsm_paths:
        print(f"\n--- Processing BSM file: {bsm_path} ---")
        ieee, bsm, ieee_hex = load_BSM(bsm_path)
        _run_detections(
            ieee, bsm, ieee_hex, os.path.basename(bsm_path),
            observations, check_names, reports,
            cert_bytes, signing_key, args.ma_key, args.debug,
        )
    print(f"\n=== Total reports generated: {len(reports)} ===")

if __name__ == "__main__":
    launch()