'''
faulty_bsm_generator.py

read encoded bsms, decode them, then randomly perturb 
'''
# internal imports 
from constants import DATA_DIR, OUTPUT_DIR
from fault_log import FaultLog
from bsm_utils import BSM, load_security
from bsm_encoder import EncoderDecoder
from faults import FaultGenerators
# type imports
from datetime import datetime
# file navigation imports
from os import path 
# data processing imports
import numpy as np

# cryptography imports
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


class FaultyBsmGenerator:
    def __init__(self, IEEE_spec, DRSC_spec, np_seed, fault, security):
        self.log = FaultLog()
        self.cache = []
        self.encoder = EncoderDecoder(IEEE_spec, DRSC_spec)
        self.security = load_security(security)

        self.mbs = FaultGenerators(include_gens=[fault])
        np.random.seed(np_seed)


    '''
    def generate( list(), str ) ==> void

    read encoded bytes, randomly perturb each message, then re-encode for writing
    '''
    def generate(self, encoded_bsms : list, object_out, output_codec : str):
        encoder = self.encoder

        # read and perturb bsms
        self.read_bsms(encoded_bsms)
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

                # sign Ieee1609Dot2Data object
                msg_out.msg = self.sign_Ieee1609Dot2Data(msg_out.msg)
                msg_out.msg = encoder.encode_IEEE(msg_out.msg, output_codec)

            else: raise Exception("Output PDU is not in [MessageFrame, IeeeDot2Data]")

    '''
    def read_bsms( list() ) ==> void

    read encoded bsm and decode, adding to cache of messages for later
    perturbance (def perturb_bsms)
    '''
    def read_bsms(self, encoded_bsms : list):
        encoder = self.encoder
        decoded_msgs = []
    
        for encoded_msg in encoded_bsms:
            decoded_bsm = encoder.decode_bsm(encoded_msg)

            cur_id = self.log.assign_id()
            cur_bsm = BSM(msg=decoded_bsm, msg_id=cur_id)
            decoded_msgs.append(cur_bsm)

        self.cache.extend(decoded_msgs)
        
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
            certificate = self.encoder.parse_certificate(self.security)
            bsm_data = self.encoder.parse_bsm(IeeeDot2Data)
            if fault.type == 'individual':
                _, fault_msg = fault.func(bsm_data)
            elif fault.type == 'security':
                _, fault_msg = fault.func(IeeeDot2Data, certificate, bsm_data)

            bsm.mb = rand_mb_ind
            bsm.mb_desc = fault_msg

            perturbed_bsms.append(bsm_data)
        return perturbed_bsms
    

    def sign_Ieee1609Dot2Data(self, IeeeDot2Data):
        """
        Steps for signing Ieee1609Dot2Data structures:
            1. Recreate the private_key by loading the .cert and .s of a pseudonym certificate
            2. Build the digest, which is a cryptographic hash of the form
                Hash( Hash(COER(tbsData)) || Hash(COER(cert)) )
            3. Sign the digest using ECDSA with the private key 
            4. Derive the digital signature (r, s) from signing the digest
            5. Add last 8 bytes of SHA-256(cert) into signer.digest
        """

        encoder = self.encoder
        def hashed_id_8(cert_coer_bytes: bytes) -> bytes:
            """last eight bytes of SHA-256 over the COER-encoded certificate, used as the 
            compact signer identifier when you don’t include the full cert.
            
            from C-ITS Certificate Overview:
                The hashedId8 is calculated by encoding a certificate as per IEEE 1609.2 section 6.4.3 
                and then taking the last eight bytes of a SHA256 hash"""
            return hashlib.sha256(cert_coer_bytes).digest()[-8:]
        
        profile = self.security
        cert_coer, s_bytes, sk_base = profile['cert_coer'], profile['s_bytes'], profile['sk_base']

        """ 1. Recreate the private_key by loading the .cert and .s of a pseudonym certificate """
        curve = ec.SECP256R1() 
        # the curve order for P-256:
        order_n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        
        # derive the private key based on certificate bundle 
        s_i = int.from_bytes(s_bytes, "big")
        sk_i = (sk_base + s_i) % order_n
        priv_key = ec.derive_private_key(sk_i, curve, default_backend())

        #   TODO might need to reset generationTime?
        """ 2. Build the digest, which is a hash of the form
                Hash( Hash(COER(tbsData)) || Hash(COER(cert)) ) """
        tbs_coer = encoder.IEEE_spec.ToBeSignedData.to_coer(IeeeDot2Data['content'][1]['tbsData'])
        # hash COER-ToBeSigned data
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(tbs_coer)
        h_tbs = digest.finalize()

        # hash COER-Certificate data
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(cert_coer)
        h_cert = digest.finalize()

        # hash appended hashed COER-encoded ToBeSigned and Certificate data (H)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(h_tbs + h_cert)
        H = digest.finalize()

        """ 3. Sign the digest using ECDSA with the private key """
        signature_der = priv_key.sign(H, ec.ECDSA(hashes.SHA256()))

        """ 4. Derive (r, s) from signing, pack into signature """
        r, s = decode_dss_signature(signature_der)
        IeeeDot2Data['content'][1]['signature'] = ('ecdsaNistP256Signature', {'rSig' : ('compressed-y-0', r.to_bytes(32, 'big')), \
                                                                                         'sSig' : s.to_bytes(32, 'big')})
        """ 5. Add last 8 bytes of SHA-256(cert) into signer.digest """
        IeeeDot2Data['content'][1]['signer'] = ('digest', hashed_id_8(cert_coer))
        return IeeeDot2Data

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


