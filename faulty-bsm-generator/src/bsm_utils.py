# bsm_utils.py
from asn.Ieee1609Dot2 import IEEE1609dot2
from asn.J2735 import DSRC

from os import listdir, path
# constants relevant to local misbehavior detection

'''
accelerationValueOutOfRange
########################################
ACCELERATION_THRESHOLD: Maximum acceleration defined 
ACCELERATION_UNAVAILABLE: Value of 2001 indicates longitudinal acceleration is not available
'''
ACCELERATION_THRESHOLD = 2001
ACCELERATION_MAX = 4002
ACCELERATION_UNAVAILABLE = 2001

'''
individualCheckLocationError 
########################################
LOC_DISTANCE_THRESHOLD: Maximum distance (L2) from grid center without violation 
MAX_MEDIAN_ENTRIES: Maximum number of logged median grid centers
'''
LOC_DISTANCE_THRESHOLD = 0
MAX_MEDIAN_ENTRIES = 10

'''
individualCheckSpeedError 
########################################
MAX_SPEED: Maximum distance (L2) from grid center without violation 
'''
MAX_SPEED = 100

'''
individualCheckHeadingError 
########################################
MAX_HEADING: Maximum value for 'heading' field
MIN_HEADING: Minimum value for 'heading' field
'''
MAX_HEADING = 360
MIN_HEADING = 0

'''
individualCheckFrequency
########################################
MIN_DELAY_MILISECONDS: Minimimum delay between BSMs of same vehicle (miliseconds)
'''
MIN_DELAY_MILISEONDS = 100

'''
securityHeaderIncWithSecurityProfile
########################################
'''
VALID_ID = 20


'''
bsm.py

class for Basic Safety Message
'''
class BSM:
    def __init__(self, msg, msg_id):
        self.msg = msg
        self.msg_id = msg_id
        self.mb = None
        self.mb_desc = None

def parse_bsm(bytes):
    # Assuming IEEE 1609.2 and J2735 WAVE message definitions
    ieee1609Dot2Data = IEEE1609dot2.Ieee1609Dot2Data
    ieee1609Dot2Data.from_coer_ws(bytes)
    print(IEEE1609dot2.Ieee1609Dot2Data.to_jer(ieee1609Dot2Data.get_val()))
    
    bsm = DSRC.BasicSafetyMessage
    bsm.from_uper_ws(ieee1609Dot2Data.get_val()['content'][1]['tbsData']['payload']['data']['content'][1])

    core_data = bsm.get_val()['coreData']
    return core_data


def load_security(security_path):
    for f in listdir('./data/keys'):
        if path.isdir(f):
            break

    cert_coer = open(f"./data/keys/{f}/download/{security_path}/{security_path}_0.cert", "rb").read()
    s_bytes   = open(f"./data/keys/{f}/download/{security_path}/{security_path}_0.s", "rb").read()          # big-endian scalar
    sk_base   = int.from_bytes(open(f"./data/keys/{f}/dwnl_sgn.priv", "rb").read(), "big")
    return {"cert_coer" : cert_coer,\
            "s_bytes" : s_bytes, \
            "sk_base" : sk_base}