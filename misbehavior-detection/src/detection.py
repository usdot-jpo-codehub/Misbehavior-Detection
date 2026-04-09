import argparse
import ctypes
import glob
import hashlib
import json
import os
import sys

import encoder_utils, decoder_utils
from asn1c_bridge import load_lib, get_td, RC_OK
from signing_utils import load_signing_key, select_pseudonym_cert, select_rsu_cert
from utils import OBS_TITLES

_cert_cache = {}


def _compute_hashedid8(lib, cert_json_dict):
    """Return the HashedId8 hex string for a certificate: SHA-256(OER(cert))[-8:]."""
    cert_td = get_td(lib, "Certificate")
    cert_jer = json.dumps(cert_json_dict).encode()
    sptr, rval = decoder_utils.decode_jer(lib, cert_td, cert_jer)
    if rval.code != RC_OK:
        return None
    cert_oer = encoder_utils.encode_oer(lib, cert_td, sptr)
    return hashlib.sha256(cert_oer).digest()[-8:].hex().upper()


def load_BSM(filepath):
    lib = ctypes.CDLL(f"libs/asn1clib.so")
    td = get_td(lib, "Ieee1609Dot2Data")

    data = open(filepath, "rb").read()
    data_hex = data.hex()
    sptr, rval = decoder_utils.decode_oer(lib, td, data)
    # Debug
    print(f"OER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"OER decode failed")
    ieee_jer = encoder_utils.encode_jer(lib, td, sptr)
    ieee_dict = json.loads(ieee_jer)

    signer = ieee_dict.get("content", {}).get("signedData", {}).get("signer", {})
    if "certificate" in signer:
        cert_json = signer["certificate"][0]
        hashedid8 = _compute_hashedid8(lib, cert_json)
        if hashedid8:
            _cert_cache[hashedid8] = cert_json
    elif "digest" in signer:
        digest_hex = signer["digest"].upper()
        if digest_hex in _cert_cache:
            ieee_dict["content"]["signedData"]["signer"] = {"certificate": [_cert_cache[digest_hex]]}
            ieee_jer_mod = json.dumps(ieee_dict).encode()
            sptr_mod, rval_mod = decoder_utils.decode_jer(lib, td, ieee_jer_mod)
            if rval_mod.code == RC_OK:
                data_hex = encoder_utils.encode_oer(lib, td, sptr_mod).hex()

    message_frame_hex = ieee_dict["content"]["signedData"]["tbsData"]["payload"]["data"]["content"]["unsecuredData"]
    message_frame = bytes.fromhex(message_frame_hex)

    lib = ctypes.CDLL(f"libs/MessageFrame.so")
    td = get_td(lib, "MessageFrame")
    sptr, rval = decoder_utils.decode_uper(lib, td, message_frame)
    # Debug
    print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed")
    message_frame_jer = encoder_utils.encode_jer(lib, td, sptr)
    message_frame = json.loads(message_frame_jer)
    
    basicsafety_hex = message_frame.get("value", {})
    basicsafety = bytes.fromhex(basicsafety_hex)
    td = get_td(lib, "BasicSafetyMessage")
    sptr, rval = decoder_utils.decode_uper(lib, td, basicsafety)
    # Debug
    print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed")
    bsm_jer = encoder_utils.encode_jer(lib, td, sptr)
    bsm = json.loads(bsm_jer)
    bsm = {"BasicSafetyMessage": bsm}
    message_frame['value'] = bsm
    return ieee_dict, message_frame, data_hex


def launch():
    parser = argparse.ArgumentParser(description='run misbehavior detection')
    parser.add_argument('-m', '--misbehaviors', type=str, nargs='+',
                        help='space-separated list of misbehaviors to check',
                        default=['acceleration-ValueOutofRange'])
    parser.add_argument('-b', '--bsm', type=str,
                        help='path to a BSM .coer file OR a directory containing .coer files',
                        default='data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer')
    parser.add_argument('-c', "--certs-dir",
                        help="SCMS bundle directory. For RSU bundles (rsu-*/downloadFiles/ layout) "
                        "the currently valid cert is selected automatically. For pseudonym bundles "
                        "(download/{i}/{i}_{j}.cert layout with sgn_expnsn.key) butterfly expansion "
                        "is applied automatically. Detection is based on the presence of download/.",)
    parser.add_argument('--ma-key', type=str, default=None,
                        help='path to the MA recipient certificate file (e.g. certs/ma_public_key.cert)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='optional flag to output reports as JER')

    args = parser.parse_args()

    observations = []
    for misbehavior_type in args.misbehaviors: 
        if misbehavior_type in OBS_TITLES: 
            observations.append(OBS_TITLES[misbehavior_type])
        else: 
            raise Exception("{CUR_TITLE} not a valid observation name!".format(CUR_TITLE=misbehavior_type))

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

    # Resolve input BSM paths (single file or directory)
    bsm_input = args.bsm
    if os.path.isdir(bsm_input):
        bsm_paths = sorted(glob.glob(os.path.join(bsm_input, "*.coer")))
        if not bsm_paths:
            raise SystemExit(f"No .coer files found in directory: {bsm_input}")
        print(f"Found {len(bsm_paths)} .coer files in directory: {bsm_input}")
    else:
        if not os.path.isfile(bsm_input):
            raise SystemExit(f"BSM path does not exist: {bsm_input}")
        bsm_paths = [bsm_input]

    reports = []

    for bsm_path in bsm_paths:
        print(f"Processing BSM file: {bsm_path}")
        ieee, bsm, ieee_hex = load_BSM(bsm_path)
        for observation in observations:
            detections = observation.analyze_bsm(ieee, bsm, ieee_hex)
            for detection in detections:
                target_id, observation_id, evidence = detection
                mbr = observation.generate_report(target_id, observation_id, evidence, cert_bytes, signing_key, args.ma_key)
                reports.append(mbr)
                if args.debug:
                    observation.print_report()
                    observation.debug_report()
                # Output report to .COER file
                os.makedirs("output", exist_ok=True)
                coer_path = f"output/mbr-{observation.report_type}-{len(reports)}.coer"
                with open(coer_path, "wb") as f:
                    f.write(mbr)
                print(f"Wrote {coer_path}")

# __name__
if __name__=="__main__":
    launch()