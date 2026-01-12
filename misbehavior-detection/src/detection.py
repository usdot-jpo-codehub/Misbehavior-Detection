import argparse
import ctypes
import glob
import json
import os

import encoder_utils, decoder_utils
from asn1c_bridge import load_lib, get_td, RC_OK
from utils import OBS_TITLES

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
    
    message_frame_hex = ieee_dict["content"]["signedData"]["tbsData"]["payload"]["data"]["content"]["unsecuredData"]
    message_frame = bytes.fromhex(message_frame_hex)

    lib = ctypes.CDLL(f"libs/MessageFrame.so")
    td = get_td(lib, "MessageFrame")
    sptr, rval = decoder_utils.decode_uper(lib, td, message_frame)
    # Debug
    # print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed")
    bsm_jer = encoder_utils.encode_jer(lib, td, sptr)
    bsm = json.loads(bsm_jer)
    return ieee_dict, bsm, data_hex


def launch():
    parser = argparse.ArgumentParser(description='run misbehavior detection')
    parser.add_argument('-m', '--misbehaviors', type=str, nargs='+',
                        help='space-separated list of misbehaviors to check',
                        default=['acceleration-ValueOutofRange'])
    parser.add_argument('-b', '--bsm', type=str,
                        help='path to a BSM .coer file OR a directory containing .coer files',
                        default='data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='optional flag to output reports as JER')
    args = parser.parse_args()

    observations = []
    for misbehavior_type in args.misbehaviors: 
        if misbehavior_type in OBS_TITLES: 
            observations.append(OBS_TITLES[misbehavior_type])
        else: 
            raise Exception("{CUR_TITLE} not a valid observation name!".format(CUR_TITLE=misbehavior_type))

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
                reports.append(observation.generate_report(target_id, observation_id, evidence))
                if args.debug:
                    observation.print_report()
                    observation.debug_report()
                # TODO: Output report to COER encoded file

# __name__
if __name__=="__main__":
    launch()