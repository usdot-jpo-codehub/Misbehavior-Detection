# bsm_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from asn.Ieee1609Dot2 import IEEE1609dot2
from asn.J2735 import DSRC

from shapely.geometry import Point
from shapely.prepared import prep
import geopandas as gpd
import numpy as np
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

def get_coords_outside_region(code_str, margin_deg=5):
    # load country with geopandas
    
    url = "https://naciscdn.org/naturalearth/110m/cultural/ne_110m_admin_0_countries.zip"
    world = gpd.read_file(url).to_crs("EPSG:4326")  # lon/lat WGS84

    c = world[world["ISO_N3"] == code_str]
    # load country geometry
    country_geom = c.geometry.unary_union
    country_prepped = prep(country_geom)

    minx, miny, maxx, maxy = country_geom.bounds
    minx -= margin_deg; miny -= margin_deg; maxx += margin_deg; maxy += margin_deg

    pts = None
    while pts is None:
        lon = int(np.random.uniform(minx, maxx))
        lat = int(np.random.uniform(miny, maxy))
        if not country_prepped.covers(Point(lon, lat)):
            pts = (lat, lon)
    
    return pts


def load_security(iValue="23A", jValue=0):
    for f in listdir('./data/keys'):
        if path.isdir(f):
            break
    
    cert_coer = open(f"./data/keys/{f}/download/{iValue}/{iValue}_{jValue}.cert", "rb").read()
    s_bytes   = open(f"./data/keys/{f}/download/{iValue}/{iValue}_{jValue}.s", "rb").read()          # big-endian scalar
    sk_base   = int.from_bytes(open(f"./data/keys/{f}/dwnl_sgn.priv", "rb").read(), "big")
    sgn_expnsn_bytes = open(f"./data/keys/{f}/sgn_expnsn.key", "rb").read()
    return {"cert_coer" : cert_coer, 
            "s_bytes" : s_bytes, 
            "sk_base" : sk_base, 
            "sgn_expnsn_bytes" : sgn_expnsn_bytes,
            "iValue" : int(iValue, 16),
            "jValue" : int(jValue)}

def expansion_scalar_aes_dm(seed_key: bytes, i: int, j: int, order_n: int) -> int:
    def _aes_ecb_block(key: bytes, block16: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        return enc.update(block16) + enc.finalize()

    if len(seed_key) not in (16, 24, 32):
        raise ValueError("seed_key must be 16/24/32 bytes for AES")

    # Profile-specific 16-byte x. Example: 8 bytes i + 8 bytes j big-endian:
    x = i.to_bytes(8, "big") + j.to_bytes(8, "big")

    out = b""
    t = 0
    while len(out) < 32:  # 32 bytes for P-256
        xt = (int.from_bytes(x, "big") + t) & ((1 << 128) - 1)
        xt_bytes = xt.to_bytes(16, "big")
        b = _aes_ecb_block(seed_key, xt_bytes)
        out += bytes(bb ^ xx for bb, xx in zip(b, xt_bytes))
        t += 1

    return int.from_bytes(out[:32], "big") % order_n

