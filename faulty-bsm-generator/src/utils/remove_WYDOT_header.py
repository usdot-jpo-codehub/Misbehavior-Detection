import argparse
from os import path
# Constants
HEADER_BYTES = 26 # WYDOT header byte length
from constants import DATA_DIR, INPUT_BSM_DIR, OUTPUT_DIR
from asn.Ieee1609Dot2 import IEEE1609dot2

# read bytes from file
def read_file(path_to_file):
    return open(path_to_file, 'rb').read()

def remove_header(file_path : str):
    file_bytes = read_file(path.join(DATA_DIR, INPUT_BSM_DIR, file_path)) 
    
    # Decode bsm into ASN structure
    bsm_bytes = file_bytes[HEADER_BYTES:]
    #bsm = self.parse_bsm(bsm_bytes)

    # Assuming IEEE 1609.2 and J2735 WAVE message definitions
    ieee1609Dot2Data = IEEE1609dot2.Ieee1609Dot2Data
    ieee1609Dot2Data.from_coer_ws(bsm_bytes)

    print(IEEE1609dot2.Ieee1609Dot2Data.to_jer(ieee1609Dot2Data.get_val()))
    fd = open(path.join(OUTPUT_DIR, f'{file_path}_no_header'), 'wb')
    fd.write(bsm_bytes)
    return ieee1609Dot2Data.get_val()


if __name__ == '__main__': 
    # Get parameters
    parser = argparse.ArgumentParser(description ='Arguments for Faulty-BSM Generator')
    parser.add_argument('-f', '--input_file',
                        type = str, default='bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin',
                        #type = str, default='encoded_out_281_illegal',
                        help ='name of the input file (in /data/example_bsm)')

    
    args = parser.parse_args()
    remove_header(args.input_file)