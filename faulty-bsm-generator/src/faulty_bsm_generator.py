'''
faulty_bsm_generator.py

read encoded bsms, decode them, then randomly perturb 
'''
# internal imports 
from utils.constants import DATA_DIR, OUTPUT_DIR
from fault_log import FaultLog
from utils.bsm_utils import BSM, load_security, expansion_scalar_aes_dm
from bsm_encoder import EncoderDecoder
from data_signer import DataSigner
from faults import FaultGenerators
# type imports
from datetime import datetime
# file navigation imports
from os import path 
# data processing imports
import numpy as np


class FaultyBsmGenerator:
    def __init__(self, IEEE_spec, DRSC_spec, np_seed, fault, bundle, validate):
        self.log = FaultLog()
        self.cache = []
        self.encoder = EncoderDecoder(IEEE_spec, DRSC_spec)
        self.signer = DataSigner(bundle, self.encoder, validate=validate)

        self.mbs = FaultGenerators(include_gens=[fault])
        np.random.seed(np_seed)


    '''
    def generate( list(), str ) ==> void

    read encoded bytes, randomly perturb each message, then re-encode for writing
    '''
    def generate(self, encoded_bsms : list, object_out, output_codec : str, input_codec = "coer"):
        encoder = self.encoder

        # read and perturb bsms
        self.read_bsms(encoded_bsms, input_codec=input_codec)
        bsms = self.perturb_bsms_random()

        # depending on user preference, insert BSM into IeeeDot2Data or
        # return the MessageFrame for writing 
        for i, msg_out in enumerate(self.cache):
            cur_bsm = bsms[i]
            
            if object_out == "MessageFrame":
                encoded_bsm = encoder.encode_bsm(cur_bsm, output_codec)
                msg_out.msg = encoded_bsm
                
            elif object_out == "IeeeDot2Data":
                encoded_bsm = encoder.encode_bsm(cur_bsm, 'per')
                msg_out.msg['content'][1]['tbsData']['payload']['data']['content'] = ('unsecuredData', encoded_bsm)

                # TODO: sign Ieee1609Dot2Data object
                msg_out.msg = self.signer.sign_Ieee1609Dot2Data(msg_out.msg, encoder)
                msg_out.msg = encoder.encode_IEEE(msg_out.msg, output_codec)

            else: raise Exception("Output PDU is not in [MessageFrame, IeeeDot2Data]")

    '''
    def read_bsms( list() ) ==> void

    read encoded bsm and decode, adding to cache of messages for later
    perturbance (def perturb_bsms)
    '''
    def read_bsms(self, encoded_bsms : list, input_codec='coer'):
        encoder = self.encoder
        decoded_msgs = []
    
        for encoded_msg in encoded_bsms:
            decoded_bsm = encoder.decode_bsm(encoded_msg, input_codec=input_codec)
            decoded_msgs.append(decoded_bsm)
        self.process_incoming_bsms(decoded_msgs)

    def process_incoming_bsms(self, decoded_bsms):
        for bsm in decoded_bsms:
            cur_id = self.log.assign_id()
            cur_bsm = BSM(msg=bsm, msg_id=cur_id)
            self.cache.append(cur_bsm)
        
    '''
    def read_bsms

    read encoded bsm and decode, adding to cache of messages for later
    perturbance (def perturb_bsms)
    '''
    def perturb_bsms_random(self):
        decoded_bsms = self.cache
        valid_mbs = self.mbs.faults

        perturbed_bsms = []

        for bsm in decoded_bsms:
            rand_mb_ind = np.random.randint(0, len(valid_mbs))
            fault = valid_mbs[rand_mb_ind]
            
            IeeeDot2Data = bsm.msg
            certificate = self.encoder.parse_certificate(self.signer)
            bsm_data = self.encoder.parse_bsm(IeeeDot2Data)

            if fault.type == 'individual' or fault.type == "none":
                _, fault_msg = fault.func(bsm_data)
            elif fault.type == 'security':
                _, fault_msg = fault.func(IeeeDot2Data, certificate, bsm_data)

            bsm.mb = rand_mb_ind
            bsm.mb_desc = fault_msg

            perturbed_bsms.append(bsm_data)
        return perturbed_bsms
    

    '''
    def write_bsms

    write encoded faulty-bsms to file
    '''
    def write_bsms(self):
        loaded_bsms = self.cache
        log = self.log

        for msg in loaded_bsms:
            cur_id, cur_mb, cur_desc = msg.msg_id, msg.mb, msg.mb_desc
            # write id and misbehavior to log
            log.write_to_log([cur_id, cur_mb, cur_desc, str(datetime.now())])
            fd = open(path.join(OUTPUT_DIR, 'encoded_out_{ID}'.format(ID=cur_id)), 'wb')
            fd.write(msg.msg)


    def clear(self):
        self.cache = []

