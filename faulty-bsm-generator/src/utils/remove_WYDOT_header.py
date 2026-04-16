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
    #file_bytes = read_file(path.join(DATA_DIR, INPUT_BSM_DIR, file_path)) 
    file_bytes = bytes.fromhex("038081b1001480ad562fa8400039e8e717090f9665fe1bacc37ffffffff0003bbafdfa1fa1007fff8000000000020214c1c100417ffffffe824e100a3fffffffe8942102047ffffffe922a1026a40143ffe95d610423405d7ffea75610322c0599ffeadfa10391c06b5ffeb7e6103cb40a03ffed2121033bc08adffed9a6102e8408e5ffede2e102bdc0885ffedf0a1000bc019bfff7f321ffffc005dfffc55a1ffffffffffffdd1a100407fffffffe1a2fffe0000")
    
    # Decode bsm into ASN structure
    # Assuming IEEE 1609.2 and J2735 WAVE message definitions
    for num_bytes in range(0, 100):
        try:
            test_msg = file_bytes[num_bytes:]
            ieee1609Dot2Data = IEEE1609dot2.Ieee1609Dot2Data
            ieee1609Dot2Data.from_coer_ws(test_msg)
            print(IEEE1609dot2.Ieee1609Dot2Data.to_jer(ieee1609Dot2Data.get_val()))

            print(f"success: {num_bytes} bytes to decode")
            break
        except Exception as e:
            print(f"error on {num_bytes} bytes: {e}")

    # develop    


    print(IEEE1609dot2.Ieee1609Dot2Data.to_jer(ieee1609Dot2Data.get_val()))
    fd = open(path.join(OUTPUT_DIR, f'{file_path}_no_header'), 'wb')
    fd.write(file_bytes[num_bytes:])

    print("original COER: ", file_bytes.hex().upper())
    print("cleaned COER: ", file_bytes[num_bytes:].hex().upper())
    return ieee1609Dot2Data.get_val()


if __name__ == '__main__': 
    # Get parameters
    parser = argparse.ArgumentParser(description ='Arguments for Faulty-BSM Generator')
    parser.add_argument('-f', '--input_file',
                        type = str, default='bsmLogDuringEvent_1582235136_563_0320.bin',
                        #type = str, default='encoded_out_281_illegal',
                        help ='name of the input file (in /data/example_bsm)')

    
    args = parser.parse_args()
    remove_header(args.input_file)