from faulty_bsm_generator import FaultyBsmGenerator
from utils.asn.J2735 import DSRC
from utils.asn.Ieee1609Dot2 import IEEE1609dot2
from utils.constants import DATA_DIR, INPUT_BSM_DIR

import argparse
from os import path

import pycrate_asn1c.asnobj
pycrate_asn1c.asnobj.STRICT_MODE = False
pycrate_asn1c.asnobj.ASN1Obj._SAFE_BND = False
#from pycrate_asn1rt.utils import get_at

# constants
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



# read bytes from file
def read_file(path_to_file):
    return open(path_to_file, 'rb').read()

def run_generator(args):
    # create FaultyBSM object and read file
    faulty_generator = FaultyBsmGenerator(IEEE_SPEC, DRSC_SPEC, args.seed, args.fault, args.bundle, args.validate)
    file_bytes = read_file(path.join(DATA_DIR, INPUT_BSM_DIR, args.input_file)) 
    # run generator with input / output codec
    faulty_generator.generate([file_bytes for _ in range(0, args.repeat_files)], 
                              object_out="IeeeDot2Data", output_codec=args.output_codec.lower())
    faulty_generator.write_bsms()


if __name__ == '__main__': 
    # Get parameters
    parser = argparse.ArgumentParser(description ='Arguments for Faulty-BSM Generator')
    parser.add_argument('-f', '--input_file',
                        type = str, default='bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header',
                        #type = str, default='encoded_out_281_illegal',
                        help ='name of the input file (in /data/example_bsm)')
    parser.add_argument('-o', '--output_codec',
                        type = str, default='COER',
                        help ='codec to encode file to (COER, PER, JER)')
    parser.add_argument('-c', '--repeat_files',
                        type = int, default=20,
                        help ='number of times to copy incoming file')
    # parser.add_argument('-t', '--object_out',
    #                     type = str, default='IeeeDot2Data',
    #                     help ='output IeeeDot2Data or MessageFrame')
    parser.add_argument('-s', '--seed',
                        type = int, default=2026,
                        help ='numpy random seed for predictable randomness')
    parser.add_argument('-m', '--fault',
                        type = str, default="perturb_security_message_inc_with_ssp",
                        help ='fault to apply to BSM')
    parser.add_argument('-v', '--validate',
                        type = bool, default=False,
                        help ='validate signed messages via SCMS (requires API_KEY env variable to be set)')
    parser.add_argument('-b', '--bundle',
                        type = str, default='eebb92918c25d907',
                        help ='bundle digest (for load from bundle path)')

    
    args = parser.parse_args()
    run_generator(args)