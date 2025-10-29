'''
bsm_encoder.py 

provided a spec:
    (1) decode corresponding files from asn1c / per / der / jer 
    (2) load into spec
    (3) encode into asn1c / per / der / jer 
'''

# Constants
HEADER_BYTES = 26


class EncoderDecoder:
    def __init__(self, IEEE_spec, DSRC_spec):
        self.IEEE_spec = IEEE_spec
        self.DSRC_spec = DSRC_spec

    def spec_decode(self, spec, encoded_file, codec):
        decode_func = None
        if codec == 'per': decode_func = spec.from_uper_ws
        elif codec == 'der': decode_func = spec.from_der_ws
        elif codec == 'jer': decode_func = spec.from_jer
        elif codec == 'asn1': decode_func = spec.from_asn
        elif codec == 'coer': decode_func = spec.from_coer_ws
        else: raise Exception("codec not supported")
        
        # attempt to decode
        decode_func(encoded_file)

    
    def decode_bsm(self, encoded_file : str):
        IEEE1609dot2 = self.IEEE_spec

        # If header exists, parse header 
        if HEADER_BYTES > 0: 
            header_bytes = encoded_file[:HEADER_BYTES]
            header = parse_header(header_bytes)
            # Do something with header if needed
        
        # Decode bsm into ASN structure
        bsm_bytes = encoded_file[HEADER_BYTES:]
        #bsm = self.parse_bsm(bsm_bytes)

        # Assuming IEEE 1609.2 and J2735 WAVE message definitions
        ieee1609Dot2Data = IEEE1609dot2.Ieee1609Dot2Data
        ieee1609Dot2Data.from_coer_ws(bsm_bytes)

        print(IEEE1609dot2.Ieee1609Dot2Data.to_jer(ieee1609Dot2Data.get_val()))
        return ieee1609Dot2Data.get_val()
        
    
    def encode_bsm(self, decoded_file : str, codec : str):
        spec = self.DSRC_spec.MessageFrame
        spec.set_val(decoded_file)

        encode_func = None
        if codec == 'per': encode_func = spec.to_uper_ws
        elif codec == 'der': encode_func = spec.to_der_ws
        elif codec == 'jer': encode_func = spec.to_jer
        elif codec == 'asn1': encode_func = spec.to_asn
        else: raise Exception("codec not supported")

        encode_msg = encode_func(decoded_file)
        return encode_msg
    
    
    def encode_IEEE(self, decoded_file : str, codec : str):
        spec = self.IEEE_spec.Ieee1609Dot2Data
        spec.set_val(decoded_file)

        encode_func = None
        if codec == 'per': encode_func = spec.to_uper_ws
        elif codec == 'der': encode_func = spec.to_der_ws
        elif codec == 'jer': encode_func = spec.to_jer
        elif codec == 'asn1': encode_func = spec.to_asn
        elif codec == 'coer': encode_func = spec.to_coer_ws
        else: raise Exception("codec not supported")

        encode_msg = encode_func(decoded_file)

        if codec == 'jer': encode_msg = encode_msg.encode('utf-8')
        return encode_msg


    def parse_bsm(self, ieee1609Dot2Data):
        DSRC = self.DSRC_spec
        bsm = DSRC.MessageFrame
        
        bsm.from_uper_ws(ieee1609Dot2Data['content'][1]['tbsData']['payload']['data']['content'][1])
        # return bsm
        return bsm.get_val()
    
    def parse_certificate(self, certificate):
        IEEE = self.IEEE_spec

        cert = IEEE.Certificate
        cert.from_coer(certificate['cert_coer'])
        # return bsm
        return cert.get_val()


    def print_bsm(self, bsm):
        print(self.DSRC_spec.BSMcoreData.to_jer(bsm))


def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)


def bytes_to_hex(byte_string):
    return byte_string.hex()

def parse_header(header):
    # WYDOT bsms 26 bytes long
    # wydotLogRecords.h
    pass
