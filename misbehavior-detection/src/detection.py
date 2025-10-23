import argparse
import ctypes
import json
import encoder_utils, decoder_utils
from asn1c_bridge import load_lib, get_td, RC_OK
from utils import OBS_TITLES


def load_BSM(filepath):
    lib = ctypes.CDLL(f"libs/asn1clib.so")
    td = get_td(lib, "Ieee1609Dot2Data")

    data = open(filepath, "rb").read()
    sptr, rval = decoder_utils.decode_oer(lib, td, data)
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
    print(f"UPER decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != 0:
        raise SystemExit(f"UPER decode failed")
    bsm_jer = encoder_utils.encode_jer(lib, td, sptr)
    bsm = json.loads(bsm_jer)
    return bsm, message_frame_hex


def launch():
    parser = argparse.ArgumentParser(description='run misbehavior detection')
    parser.add_argument('-m', '--misbehaviors', type=str, nargs ='+', help='space-seperated list of misbehaviors to check', default=['acceleration-ValueOutofRange'])
    parser.add_argument('-b', '--bsm', type=str, help='name of basic safety message (bsm) file', default='data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer')
    parser.add_argument('-d', '--debug', action='store_true', help='optional flag to output reports as JER')
    args = parser.parse_args()

    observations = []
    for misbehavior_type in args.misbehaviors: 
        if misbehavior_type in OBS_TITLES: observations.append(OBS_TITLES[misbehavior_type])
        else: raise Exception("{CUR_TITLE} not a valid observation name!".format(CUR_TITLE=misbehavior_type))

    bsm, bsm_hex = load_BSM(args.bsm)

    reports = []

    for observation in observations:
        detections = observation.analyze_bsm(bsm, bsm_hex)
        for detection in detections:
            target_id, observation_id, evidence = detection
            reports.append(observation.generate_report(target_id, observation_id, evidence))
            if args.debug:
                observation.print_report()
                observation.debug_report()

# __name__
if __name__=="__main__":
    launch()