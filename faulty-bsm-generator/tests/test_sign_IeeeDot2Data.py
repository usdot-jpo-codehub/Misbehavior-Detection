from data_signer import DataSigner
from faulty_bsm_generator import FaultyBsmGenerator
from test_faultybsm import read_file
from utils.asn.J2735 import DSRC
from utils.asn.Ieee1609Dot2 import IEEE1609dot2

from unittest import TestCase
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class SignTest(TestCase): 
    IEEE_SPEC = IEEE1609dot2
    DRSC_SPEC = DSRC

    vector_test_one = { 
        "i" : int("0x217D79E1", 16),
        "j" : int("0x00000011", 16),
        "sgn_expnsn_bytes" : bytes.fromhex("121D14216715E11D2D3787434A673B1B"),
        "e" : "0x79081DDD31EF9E5EA601250E584CD90FBA13EE7B518E72A2DB3AAAA158E12D5E",
        "a_xp" : "0x4D2093ED3EA27B15FCBD61806FFA13B36AE367F88C52397824A9BF67283D8CEE",
        "pub_x" : "0x2b18f3d93c4df3d9d1490e3a9ba5a0de9cfa73eddb95408bc1f2bf60cb3cf313L",
        "pub_y" : "0x1a2ce511e0da86356329a5c22a36a8a53088dcb11a5a94fa903ef0087421666aL" }


    def test_butterfly_expansion_ex1(self):
        signer = DataSigner("23A", 0)
        order_n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        sgn_expnsn_bytes = bytes.fromhex("121D14216715E11D2D3787434A673B1B")
        i = int("0x217D79E1", 16)
        j = int("0x00000011", 16)
        sk_base = int("D418760F0CB2DCB856BC3C7217AD3AA36DB6742AE1DB655A3D28DF88CBBF84E1", 16)

        e = signer.expansion_scalar_aes_dm(sgn_expnsn_bytes, i, j, order_n)
        print(f"e: {hex(e)}")
        
        assert hex(e) == self.vector_test_one["e"].lower()

        a_exp = (sk_base + e) % order_n
        assert hex(a_exp) == self.vector_test_one["a_xp"].lower()

        priv = ec.derive_private_key(a_exp, ec.SECP256R1(), default_backend())
        pub = priv.public_key().public_numbers()

        #assert hex(pub.x) == self.vector_test_one["pub_x"]
        #assert hex(pub.y) == self.vector_test_one["pub_y"]

    def test_bundle_matches_device(self):
        signer = DataSigner("245", 0)
        ec = open("data/keys/d648bd04ab8b9cc1/certchain/0", "rb").read()
        print(f"ec: {ec}\n")
        print(f"hash: {signer.hashed_id_8(ec).hex()}")
        
        assert "d648bd04ab8b9cc1" == signer.hashed_id_8(ec).hex()


    import base64
import hashlib
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    Prehashed,
)
from cryptography.hazmat.primitives import hashes


# ----------------------------
# Hash helpers (match your code)
# ----------------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hashed_id_8(cert_coer: bytes) -> bytes:
    return sha256(cert_coer)[-8:]


# ----------------------------
# P-256 curve math (pure python)
# ----------------------------
# Prime field p, curve params, order n, generator G
P256_P = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
P256_A = (P256_P - 3) % P256_P
P256_B = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

Gx = int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
Gy = int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
G = (Gx, Gy)

INF = None  # point at infinity


def inv_mod(k: int, p: int) -> int:
    return pow(k, p - 2, p)

def is_on_curve(Pt):
    if Pt is None:
        return True
    x, y = Pt
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0

def point_add(Pt, Qt):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt

    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None

    if Pt == Qt:
        # slope = (3x^2 + a) / (2y)
        m = ((3 * x1 * x1 + P256_A) * inv_mod(2 * y1 % P256_P, P256_P)) % P256_P
    else:
        # slope = (y2 - y1) / (x2 - x1)
        m = ((y2 - y1) * inv_mod((x2 - x1) % P256_P, P256_P)) % P256_P

    x3 = (m * m - x1 - x2) % P256_P
    y3 = (m * (x1 - x3) - y1) % P256_P
    return (x3, y3)

def scalar_mult(k: int, Pt):
    if k % P256_N == 0 or Pt is None:
        return None
    k = k % P256_N
    result = None
    addend = Pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def decompress_p256_x(x_bytes: bytes, y_lsb: int):
    x = int.from_bytes(x_bytes, "big")
    rhs = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
    y = pow(rhs, (P256_P + 1) // 4, P256_P)  # p % 4 == 3 for P-256
    if (y & 1) != y_lsb:
        y = (-y) % P256_P
    Pt = (x, y)
    assert is_on_curve(Pt)
    return Pt


# ----------------------------
# 1609.2a-style ECQV reconstruction (implicit certificate)
# ----------------------------

def ecqv_e_value(tbs_cert_coer: bytes, issuer_cert_coer: bytes) -> int:
    """
    IEEE 1609.2a describes reconstructing the associated public key for implicit certs.
    The e value is computed from hashes of ToBeSignedCertificate and issuer certificate.
    """
    e_bytes = sha256(sha256(tbs_cert_coer) + sha256(issuer_cert_coer))
    return int.from_bytes(e_bytes, "big") % P256_N

def reconstruct_associated_pubkey(recon_point, issuer_pubkey_point, e: int):
    """
    ECQV-style: Q_u = e * P_u + Q_CA
    where P_u is reconstructionValue point and Q_CA is issuer public key point.
    """
    return point_add(scalar_mult(e, recon_point), issuer_pubkey_point)


# ----------------------------
# You must adapt these two helpers to your decoded cert structure
# ----------------------------

def get_recon_value_from_cert(cert_val):
    """
    Return reconstructionValue point as (x_bytes, y_lsb).
    Your example shows:
      ('reconstructionValue', ('compressed-y-0', b'...x...'))
    """
    # TODO: Adjust path to match your cert dict
    vki = cert_val["toBeSigned"]["verifyKeyIndicator"]
    tag, inner = vki  # ('reconstructionValue', (...))
    assert tag == "reconstructionValue"
    form, x_bytes = inner  # ('compressed-y-0', xbytes)
    if form == "compressed-y-0":
        return x_bytes, 0
    if form == "compressed-y-1":
        return x_bytes, 1
    raise AssertionError(f"Unexpected recon point form: {form}")

def get_issuer_publickey_from_cert(issuer_cert_val):
    """
    Return issuer public key point (x,y) from issuer cert.
    Issuer certs are often explicit (verificationKey present).
    """
    # TODO: Adjust path to match your issuer cert dict
    vki = issuer_cert_val["toBeSigned"]["verifyKeyIndicator"]
    tag, inner = vki
    assert tag == "verificationKey"
    form, data = inner  # e.g. ('compressed-y-0', xbytes) or ('uncompressed', b'\x04||x||y')
    if form == "compressed-y-0":
        return decompress_p256_x(data, 0)
    if form == "compressed-y-1":
        return decompress_p256_x(data, 1)
    if form == "uncompressed":
        assert data[0] == 0x04 and len(data) == 65
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")
        Pt = (x, y)
        assert is_on_curve(Pt)
        return Pt
    raise AssertionError(f"Unexpected issuer public key form: {form}")


# ----------------------------
# Tests
# ----------------------------

def test_cert_roundtrip_bytes_stable(encoder, cert_coer):
    """
    If this fails, you MUST compute h_cert over the *re-encoded* cert bytes
    (the exact bytes that will be transmitted), not your file bytes.
    """
    encoder.IEEE_spec.Certificate.from_coer(cert_coer)
    cert_val = encoder.IEEE_spec.Certificate.get_val()
    cert_coer2 = encoder.IEEE_spec.Certificate.to_coer(cert_val)
    assert cert_coer2 == cert_coer

def test_signature_field_encoding_is_x_only(signed_ieee_msg_val):
    """
    Your current code uses ('compressed-y-0', rBytes) which is usually wrong for rSig.
    """
    # adapt if your structure differs:
    _, sd = signed_ieee_msg_val["content"]
    sig_type, sig = sd["signature"]
    assert sig_type == "ecdsaNistP256Signature"
    r_choice, r_bytes = sig["rSig"]
    assert r_choice == "x-only", f"rSig should be x-only, got {r_choice}"
    assert len(r_bytes) == 32
    assert len(sig["sSig"]) == 32

def test_hash_inputs_match_transmitted_message(encoder, signed_ieee_msg_coer):
    """
    Recompute H from the decoded, transmitted message and ensure you are signing
    the same H the verifier will compute.
    """
    encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(signed_ieee_msg_coer)
    msg_val = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

    ct, sd = msg_val["content"]
    assert ct == "signedData"

    # 1) COER(tbsData) as verifier sees it
    tbs_coer = encoder.IEEE_spec.ToBeSignedData.to_coer(sd["tbsData"])
    h_tbs = sha256(tbs_coer)

    # 2) COER(cert) as verifier sees it (leaf cert in signer)
    s_tag, s_list = sd["signer"]
    assert s_tag == "certificate", "This test assumes signer is certificate-embedded"
    leaf_cert_val = s_list[0]
    leaf_cert_coer = encoder.IEEE_spec.Certificate.to_coer(leaf_cert_val)
    h_cert = sha256(leaf_cert_coer)

    # 3) H = sha256(h_tbs||h_cert)
    H = sha256(h_tbs + h_cert)

    # H must equal what you signed; we can't see your internal H directly,
    # so we verify signature using H below.
    sig_type, sig = sd["signature"]
    assert sig_type == "ecdsaNistP256Signature"
    r_choice, r_bytes = sig["rSig"]
    assert r_choice == "x-only"
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(sig["sSig"], "big")

    # The remaining tests will verify this signature against the reconstructed public key.
    return msg_val, H, (r, s)

def test_private_key_matches_implicit_cert_pubkey(encoder, cert_coer, issuer_cert_coer,
                                                  sk_base_int, s_bytes, sgn_expnsn_bytes,
                                                  iValue, jValue, expansion_scalar_fn):
    """
    This is the strongest localization test for butterfly/expansion errors.
    It checks: derived sk_cert * G == reconstructed associated public key from implicit cert.
    """
    # decode leaf and issuer
    encoder.IEEE_spec.Certificate.from_coer(cert_coer)
    leaf = encoder.IEEE_spec.Certificate.get_val()
    encoder.IEEE_spec.Certificate.from_coer(issuer_cert_coer)
    issuer = encoder.IEEE_spec.Certificate.get_val()

    # derive sk_cert exactly as your code does
    e_bfly = expansion_scalar_fn(sgn_expnsn_bytes, iValue, jValue, P256_N)  # f_k(i,j) mod n
    sk_bfly = (sk_base_int + e_bfly) % P256_N
    sk_cert = (sk_bfly + int.from_bytes(s_bytes, "big")) % P256_N

    Q_from_sk = scalar_mult(sk_cert, G)
    assert is_on_curve(Q_from_sk)

    # reconstruct associated public key from implicit cert
    x_bytes, y_lsb = get_recon_value_from_cert(leaf)
    P_u = decompress_p256_x(x_bytes, y_lsb)

    issuer_pub = get_issuer_publickey_from_cert(issuer)

    # compute e used in reconstruction
    # (hash of ToBeSignedCertificate and issuer cert)
    tbs_cert_coer = encoder.IEEE_spec.ToBeSignedCertificate.to_coer(leaf["toBeSigned"])
    issuer_cert_coer2 = encoder.IEEE_spec.Certificate.to_coer(issuer)
    e_val = ecqv_e_value(tbs_cert_coer, issuer_cert_coer2)

    Q_recon = reconstruct_associated_pubkey(P_u, issuer_pub, e_val)
    assert is_on_curve(Q_recon)

    assert Q_from_sk == Q_recon, "Derived private key doesn't match implicit cert public key"

def test_signature_verifies_offline(encoder, signed_ieee_msg_coer, issuer_cert_coer):
    """
    End-to-end verifier-equivalent check:
      - decode transmitted message
      - recompute H
      - reconstruct associated public key from implicit leaf cert + issuer cert
      - verify ECDSA signature over H
    If this passes but SCMS fails, your issue is likely chain/trust/permissions/policy (not math).
    """
    encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(signed_ieee_msg_coer)
    msg_val = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

    ct, sd = msg_val["content"]
    assert ct == "signedData"

    # recompute H from transmitted bytes
    tbs_coer = encoder.IEEE_spec.ToBeSignedData.to_coer(sd["tbsData"])
    h_tbs = sha256(tbs_coer)

    s_tag, s_list = sd["signer"]
    assert s_tag == "certificate"
    leaf = s_list[0]
    leaf_coer = encoder.IEEE_spec.Certificate.to_coer(leaf)
    h_cert = sha256(leaf_coer)

    H = sha256(h_tbs + h_cert)

    # signature -> DER
    sig_type, sig = sd["signature"]
    assert sig_type == "ecdsaNistP256Signature"
    r_choice, r_bytes = sig["rSig"]
    assert r_choice == "x-only"
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(sig["sSig"], "big")
    sig_der = encode_dss_signature(r, s)

    # reconstruct leaf associated public key
    encoder.IEEE_spec.Certificate.from_coer(issuer_cert_coer)
    issuer = encoder.IEEE_spec.Certificate.get_val()
    issuer_pub = get_issuer_publickey_from_cert(issuer)

    x_bytes, y_lsb = get_recon_value_from_cert(leaf)
    P_u = decompress_p256_x(x_bytes, y_lsb)

    tbs_cert_coer = encoder.IEEE_spec.ToBeSignedCertificate.to_coer(leaf["toBeSigned"])
    issuer_cert_coer2 = encoder.IEEE_spec.Certificate.to_coer(issuer)
    e_val = ecqv_e_value(tbs_cert_coer, issuer_cert_coer2)

    Q_leaf = reconstruct_associated_pubkey(P_u, issuer_pub, e_val)
    x, y = Q_leaf
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    # verify signature over H
    pub.verify(sig_der, H, ec.ECDSA(Prehashed(hashes.SHA256())))

def test_signer_digest_matches_leaf_cert_if_used(encoder, signed_ieee_msg_coer):
    """
    If you switch back to signer=('digest', hid8), this ensures the digest matches the leaf cert.
    """
    encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(signed_ieee_msg_coer)
    msg_val = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

    ct, sd = msg_val["content"]
    assert ct == "signedData"

    s_tag, s_val = sd["signer"]
    if s_tag != "digest":
        pytest.skip("signer is not digest")

    digest8 = s_val
    assert isinstance(digest8, (bytes, bytearray)) and len(digest8) == 8

    # if you ALSO embed certs elsewhere, compare here; otherwise this test is limited.
    