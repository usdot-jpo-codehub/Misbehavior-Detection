from faulty_bsm_generator import FaultyBsmGenerator
from asn.J2735 import DSRC
from asn.Ieee1609Dot2 import IEEE1609dot2
from constants import DATA_DIR, INPUT_BSM_DIR

import argparse
from os import path

import pycrate_asn1c.asnobj
pycrate_asn1c.asnobj.STRICT_MODE = False
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
    return open(path.join(DATA_DIR, INPUT_BSM_DIR, path_to_file), 'rb').read()

def run_generator(args):
    # create FaultyBSM object and read file
    faulty_generator = FaultyBsmGenerator(IEEE_SPEC, DRSC_SPEC, args.seed, args.fault, args.security)
    file_bytes = read_file(args.input_file) 
    # run generator with input / output codec
    faulty_generator.generate([file_bytes for _ in range(0, args.repeat_files)], 
                              object_out=args.object_out, output_codec=args.output_codec)
    faulty_generator.write_bsms()


if __name__ == '__main__': 
    # Get parameters
    parser = argparse.ArgumentParser(description ='Arguments for Faulty-BSM Generator')
    parser.add_argument('-f', '--input_file',
                        type = str, default='bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin',
                        help ='name of the input file (in /data/example_bsm)')
    parser.add_argument('-o', '--output_codec',
                        type = str, default='jer',
                        help ='codec to encode file to (COER, PER, JER)')
    parser.add_argument('-c', '--repeat_files',
                        type = int, default=10,
                        help ='number of times to copy incoming file')
    parser.add_argument('-t', '--object_out',
                        type = str, default='IeeeDot2Data',
                        help ='output IeeeDot2Data or MessageFrame')
    parser.add_argument('-s', '--seed',
                        type = int, default=2024,
                        help ='numpy random seed for predictable randomness')
    parser.add_argument('-m', '--fault',
                        type = str, default="perturb_heading",
                        help ='fault to apply to BSM')
    parser.add_argument('-k', '--security',
                        type = str, default="23A",
                        help ='fault to apply to BSM')

    
    args = parser.parse_args()
    run_generator(args)