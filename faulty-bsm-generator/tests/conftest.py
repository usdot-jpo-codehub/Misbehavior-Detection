# tests/conftest.py
import json
from os import path
from pathlib import Path
import pytest

from bsm_encoder import EncoderDecoder
from asn.J2735 import DSRC
from asn.Ieee1609Dot2 import IEEE1609dot2
IEEE_SPEC = IEEE1609dot2
DRSC_SPEC = DSRC
from data_signer import DataSigner
from test_faultybsm import read_file, DATA_DIR, INPUT_BSM_DIR

# EDIT ME: import your signer class / encoder factory
# from yourpkg.signer import DataSigner
# from yourpkg.asn1 import make_encoder

DATA_ROOT = Path("data")  # EDIT ME if needed


def _read_bytes(p: Path) -> bytes:
    return p.read_bytes()


@pytest.fixture(scope="session")
def encoder():
    """
    Session-scoped: create ASN.1 encoder/decoder once.
    """
    # EDIT ME:
    # return make_encoder()
    return EncoderDecoder(IEEE_SPEC, DRSC_SPEC)



@pytest.fixture
def signer():
    """
    A fresh signer per test (function-scoped).
    """
    # EDIT ME:
    # s = DataSigner(str(cert_profile["iValue"]), cert_profile["jValue"])
    # s.cert_data = cert_profile
    # return s
    return DataSigner("245", 0)


@pytest.fixture
def unsigned_ieee_msg_val(encoder):
    """
    Build an UNSIGNED Ieee1609Dot2Data python structure that your signer expects.
    This should include:
      - content = ('signedData', {...})
      - tbsData present
      - payload contains your MessageFrame bytes (already confirmed ok)

    EDIT ME: plug in your real builder. Keep it deterministic for tests.
    """

    file_bytes = read_file(path.join(DATA_DIR, INPUT_BSM_DIR, "bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin"))
    unsigned = encoder.decode_bsm([file_bytes])
    return unsigned


@pytest.fixture
def signed_ieee_msg_val(unsigned_ieee_msg_val, signer, encoder):
    """
    The signed dict structure (easy to introspect fields).
    """
    msg = unsigned_ieee_msg_val
    return signer.sign_Ieee1609Dot2Data(msg, encoder)


@pytest.fixture
def signed_ieee_msg_coer(signed_ieee_msg_val, encoder):
    """
    The exact COER bytes you transmit to SCMS.
    """
    return encoder.IEEE_spec.Ieee1609Dot2Data.to_coer(signed_ieee_msg_val)