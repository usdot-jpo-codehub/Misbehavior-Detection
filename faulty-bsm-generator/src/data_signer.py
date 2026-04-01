from os import listdir, path, getenv
from utils.bsm_utils import expansion_scalar_aes_dm
# cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed, encode_dss_signature

import hashlib
import base64
import datetime
import requests
import json
from pathlib import Path

EPOCH_2004 = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
now_sec = int((datetime.datetime.now(datetime.timezone.utc) - EPOCH_2004).total_seconds())
now_us  = int((datetime.datetime.now(datetime.timezone.utc) - EPOCH_2004).total_seconds() * 1_000_000)

import hashlib
from pathlib import Path

    
def _sha256(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

def _hid8(cert_coer: bytes) -> bytes:
        return _sha256(cert_coer)[-8:]

def _find_cert_by_hid8(bundle_dir: str, target: bytes, encoder) -> bytes:
        bundle = Path(bundle_dir)
        roots = [bundle / "download", bundle / "certchain", bundle / "trustedcerts"]
        for root in roots:
            if not root.exists():
                continue
            for p in root.rglob("*.cert"):
                b = p.read_bytes()
                if _hid8(b) == target:
                    return b
        raise RuntimeError(f"Could not find cert with hid8={target.hex()}")

def verify_roundtrip_signeddata(IeeeDot2Data, r_int, s_int, encoder, bundle_dir: str):
        """
        Re-encode -> decode -> recompute H2 from decoded objects -> verify signature with pubkey derived from dU*G
        Assumes you already proved dU is correct and you can provide pubkey externally if you want.

        Returns H2 and cert bytes used for H2.
        """
        # encode what you actually send
        wire = encoder.IEEE_spec.Ieee1609Dot2Data.to_coer(IeeeDot2Data)

        # decode back
        encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(wire)
        rt = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

        # recompute H2 from the decoded tbsData + signer-identifier input certificate
        tbs2 = encoder.IEEE_spec.ToBeSignedData.to_coer(rt["content"][1]["tbsData"])

        signer_choice, signer_val = rt["content"][1]["signer"]
        if signer_choice == "certificate":
            cert2 = encoder.IEEE_spec.Certificate.to_coer(signer_val[0])
        elif signer_choice == "digest":
            cert2 = _find_cert_by_hid8(bundle_dir, signer_val, encoder)
        else:
            raise ValueError(f"Unhandled signer choice: {signer_choice}")

        H2 = _sha256(_sha256(tbs2) + _sha256(cert2))

        # local signature verify (with the public key corresponding to your derived private key)
        sig_der = encode_dss_signature(r_int, s_int)

        # If you still have the derived priv_key from butterfly_expansion, this is easiest:
        #   priv_key.public_key().verify(sig_der, H2, ec.ECDSA(Prehashed(hashes.SHA256())))
        #
        # Otherwise pass in / reconstruct the pubkey you used for ECQV check; for now assume you have priv_key available.
        return rt, H2, cert2

# P-256 params
P  = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
A  = P - 3
B  = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
N  = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    # P-256 generator
G = (
        int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
    )
class DataSigner:
    def __init__(self, bundle, encoder, validate=True):        
        iValue, jValue = self.find_cert_valid_now(bundle, encoder)

        
        self.bundle = bundle
        self.path_cert = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.cert"
        self.path_s = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.s"
        self.path_priv = f"./data/keys/{bundle}/dwnl_sgn.priv"
        self.path_sgn_exp = f"./data/keys/{bundle}/sgn_expnsn.key"

        self.cert_data = self.load_security(iValue, jValue)
        self.validate = validate


    def load_security(self, iValue="23A", jValue=0):         
        cert_coer = open(self.path_cert, "rb").read()
        s_bytes   = open(self.path_s, "rb").read()          # big-endian scalar
        #sk_base   = int.from_bytes(open(self.path_priv, "rb").read(), "big")
        sk_base   = open(self.path_priv, "rb").read()
        sgn_expnsn_bytes = open(self.path_sgn_exp, "rb").read()

        # print('sk_base: ', sk_base)
        # print('sk_base (len): ', len(sk_base))
        # print('s_bytes (len): ', s_bytes)
        # print('s_bytes: ', len(s_bytes))
        # print('sgn_expnsn_bytes: ', sgn_expnsn_bytes)
        # print('sgn_expnsn_bytes (len): ', len(sgn_expnsn_bytes))

        return {"cert_coer" : cert_coer, 
                "s_bytes" : s_bytes, 
                "sk_base" : sk_base, 
                "sgn_expnsn_bytes" : sgn_expnsn_bytes,
                "iValue" : int(iValue, 16),
                "jValue" : int(jValue)}
    
    def vp_end(self, vp):
        start = vp["start"]
        kind, val = vp["duration"]
        end = start + (val * 3600 if kind == "hours" else val)
        return start, end

    def find_cert_valid_now(self, bundle: str, encoder):
        download_root = f"./data/keys/{bundle}/download/"
        for p in sorted(Path(download_root).rglob("*.cert")):
            if not p.is_file():
                continue
            b = p.read_bytes()
            try:
                encoder.IEEE_spec.Certificate.from_coer(b)
                cert = encoder.IEEE_spec.Certificate.get_val()
            except Exception:
                continue

            vp = cert["toBeSigned"]["validityPeriod"]
            start, end = self.vp_end(vp)
            if start <= now_sec <= end:
                output = p.name[:-5].split("_")
                iValue, jValue = output[0], output[1]
                return iValue, jValue
        return None

    def expansion_scalar_aes_dm(self, seed_key: bytes, i: int, j: int, order_n: int) -> int:
        def _aes_ecb_block(key: bytes, block16: bytes) -> bytes:
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            enc = cipher.encryptor()
            return enc.update(block16) + enc.finalize()

        if len(seed_key) not in (16, 24, 32):
            raise ValueError("seed_key must be 16/24/32 bytes for AES")

        # Profile-specific 16-byte x. Example: 8 bytes i + 8 bytes j big-endian:
        # x = i.to_bytes(8, "big") + j.to_bytes(8, "big")
        x_cert = (0 << 96) | ((i & 0xFFFFFFFF) << 64) | ((j & 0xFFFFFFFF) << 32) | 0
        x = x_cert.to_bytes(16, "big")

        blocks = []
        for t in (1, 2, 3):  # 32 bytes for P-256
            xt = (int.from_bytes(x, "big") + t) & ((1 << 128) - 1)
            xt_bytes = xt.to_bytes(16, "big")
            ct = _aes_ecb_block(seed_key, xt_bytes)
            blocks.append(bytes(a ^ b for a, b in zip(ct, xt_bytes)))

        fk_int = int.from_bytes(b"".join(blocks), "big")   # 48 bytes
        #print(f"fk_int: {hex(fk_int)}")
        return fk_int % order_n
    
    def hashed_id_8(self, cert_coer_bytes: bytes) -> bytes:
            """last eight bytes of SHA-256 over the COER-encoded certificate, used as the 
            compact signer identifier when you don’t include the full cert.
            
            from C-ITS Certificate Overview:
                The hashedId8 is calculated by encoding a certificate as per IEEE 1609.2 section 6.4.3 
                and then taking the last eight bytes of a SHA256 hash"""
            return hashlib.sha256(cert_coer_bytes).digest()[-8:]
    
    def butterfly_expansion(
        self,
        encoder,
        IeeeDot2Data,
        cert_coer: bytes,
        s_bytes: bytes,
        sk_base,                 # int or bytes
        sgn_expnsn_bytes: bytes, # 16 bytes
        iValue: int,
        jValue: int,
        *,
        bundle_dir=None,         # optional pathlib.Path to ./data/keys/<bundle>
        debug: bool = True,
        assert_key_match: bool = False,
        normalize_low_s: bool = True,
    ):
        """
        Derive ECQV implicit-cert signing key and sign IEEE1609.2 SignedData.

        Returns:
            (r, s) ints, where signature is ECDSA over:
            H = SHA256( SHA256(COER(tbsData)) || SHA256(COER(cert_used_for_signer_id)) )
        """
        import hashlib
        from pathlib import Path
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

        # ---- curve params (P-256) ----
        _P  = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        _A  = (_P - 3) % _P
        _B  = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        _N  = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        _G  = (
            int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        )

        def _sha256(b: bytes) -> bytes:
            return hashlib.sha256(b).digest()

        def _hid8(coer_cert: bytes) -> bytes:
            return _sha256(coer_cert)[-8:]

        def _inv_mod_p(a: int) -> int:
            return pow(a, _P - 2, _P)

        def _pt_add(P1, P2):
            if P1 is None: return P2
            if P2 is None: return P1
            x1, y1 = P1
            x2, y2 = P2
            if x1 == x2 and (y1 + y2) % _P == 0:
                return None
            if P1 == P2:
                lam = (3 * x1 * x1 + _A) * _inv_mod_p(2 * y1) % _P
            else:
                lam = (y2 - y1) * _inv_mod_p(x2 - x1) % _P
            x3 = (lam * lam - x1 - x2) % _P
            y3 = (lam * (x1 - x3) - y1) % _P
            return (x3, y3)

        def _pt_mul(k: int, Pnt):
            R = None
            Q = Pnt
            while k:
                if k & 1:
                    R = _pt_add(R, Q)
                Q = _pt_add(Q, Q)
                k >>= 1
            return R

        def _decompress_p256(point_form: str, x_bytes: bytes):
            # point_form is 'compressed-y-0' or 'compressed-y-1'
            x = int.from_bytes(x_bytes, "big")
            y2 = (pow(x, 3, _P) + _A * x + _B) % _P
            y = pow(y2, (_P + 1) // 4, _P)  # since p % 4 == 3
            y_is_odd = (point_form == "compressed-y-1")
            if (y & 1) != int(y_is_odd):
                y = _P - y
            return (x, y)

        def _extract_issuer_verify_point(issuer_cert_decoded):
            """
            issuer_cert_decoded['toBeSigned']['verifyKeyIndicator'] can look like:
            ('verificationKey', ('ecdsaNistP256', ('compressed-y-0', xbytes)))
            or:
            ('verificationKey', ('compressed-y-0', xbytes))
            """
            vki = issuer_cert_decoded["toBeSigned"]["verifyKeyIndicator"]
            if vki[0] != "verificationKey":
                raise ValueError(f"Unexpected issuer verifyKeyIndicator choice: {vki[0]}")

            body = vki[1]
            # case: ('compressed-y-0', bytes)
            if isinstance(body, tuple) and len(body) == 2 and isinstance(body[0], str) and isinstance(body[1], (bytes, bytearray)):
                return body[0], bytes(body[1])

            # case: ('ecdsaNistP256', ('compressed-y-0', bytes))
            if isinstance(body, tuple) and len(body) == 2 and isinstance(body[0], str) and isinstance(body[1], tuple):
                alg, point = body
                if alg != "ecdsaNistP256":
                    raise ValueError(f"Unexpected issuer algorithm: {alg}")
                return point[0], bytes(point[1])

            raise ValueError(f"Unrecognized issuer verifyKeyIndicator structure: {vki!r}")

        def _find_issuer_cert_coer(bundle_path: Path, issuer_digest8: bytes) -> bytes:
            # Search likely places; recurse.
            roots = [
                bundle_path / "trustedcerts",
                bundle_path / "certchain",
            ]
            for root in roots:
                if not root.exists():
                    continue
                for p in root.rglob("*"):
                    if not p.is_file():
                        continue
                    b = p.read_bytes()
                    if _hid8(b) == issuer_digest8:
                        return b
            raise RuntimeError(f"Issuer cert not found for issuer HashedId8={issuer_digest8.hex()}")

        def _e_ieee1609(cert_decoded, issuer_cert_coer: bytes) -> int:
            """
            IEEE-1609-ish integer hash for implicit cert reconstruction:
            e = int( SHA256( SHA256(COER(ToBeSignedCertificate_U)) || SHA256(COER(IssuerCertificate)) ) ) mod n
            """
            tbs_sub_coer = encoder.IEEE_spec.ToBeSignedCertificate.to_coer(cert_decoded["toBeSigned"])
            h = _sha256(_sha256(tbs_sub_coer) + _sha256(issuer_cert_coer))
            return int.from_bytes(h, "big") % _N

        # ---- inputs ----
        if isinstance(sk_base, (bytes, bytearray)):
            sk_base_int = int.from_bytes(sk_base, "big")
        else:
            sk_base_int = int(sk_base)

        curve = ec.SECP256R1()

        # ---- Step 1: butterfly expansion: kU = sk_base + f(i,j) (mod n) ----
        f_ij = self.expansion_scalar_aes_dm(sgn_expnsn_bytes, iValue, jValue, _N)  
        kU = (sk_base_int + f_ij) % _N

        # ---- Decode EE cert ----
        encoder.IEEE_spec.Certificate.from_coer(cert_coer)
        ee_cert = encoder.IEEE_spec.Certificate.get_val()
        if ee_cert.get("type") != "implicit":
            raise ValueError(f"Expected implicit certificate; got type={ee_cert.get('type')}")

        # ---- Locate issuer cert bytes ----
        if bundle_dir is None:
            bundle_dir = Path("./data/keys") / self.bundle
        else:
            bundle_dir = Path(bundle_dir)

        issuer_digest8 = ee_cert["issuer"][1]  # 8 bytes
        issuer_cert_coer = _find_issuer_cert_coer(bundle_dir, issuer_digest8)

        # ---- Compute e and derive dU for implicit cert ----
        e = _e_ieee1609(ee_cert, issuer_cert_coer)
        r_ca = int.from_bytes(s_bytes, "big") % _N
        dU = (r_ca + (e * kU) % _N) % _N

        priv_key = ec.derive_private_key(dU, curve)

        # ---- Optional Debugging Test: ECQV public-key consistency check: dU*G == e*Pu + Qca ----
        if debug or assert_key_match:
            # issuer public key Qca
            encoder.IEEE_spec.Certificate.from_coer(issuer_cert_coer)
            issuer_cert = encoder.IEEE_spec.Certificate.get_val()
            qca_form, qca_x = _extract_issuer_verify_point(issuer_cert)
            Qca = _decompress_p256(qca_form, qca_x)

            # reconstruction point Pu from EE cert
            vki = ee_cert["toBeSigned"]["verifyKeyIndicator"]
            assert vki[0] == "reconstructionValue"
            pu_form, pu_x = vki[1]
            Pu = _decompress_p256(pu_form, pu_x)

            Qu = _pt_add(_pt_mul(e, Pu), Qca)
            Q_priv = _pt_mul(dU, _G)

            ok = (Q_priv == Qu)
            # print("DEBUG ECQV key check:")
            # print("  hid8(ee):", _hid8(cert_coer).hex())
            # print("  issuer hid8:", issuer_digest8.hex())
            # print("  e:", e)
            # print("  r_ca:", r_ca)
            # print("  kU:", kU)
            # print("  dU:", dU)
            # print("  dU*G == e*Pu + Qca ?", ok)

            if assert_key_match and not ok:
                raise AssertionError("ECQV key check failed: derived private key does not match implicit cert public key")

        # ---- Step 2: build H for SPDU signature ----
        tbs_coer = encoder.IEEE_spec.ToBeSignedData.to_coer(IeeeDot2Data["content"][1]["tbsData"])

        cert_for_hash = encoder.IEEE_spec.Certificate.to_coer(ee_cert)

        H = _sha256(_sha256(tbs_coer) + _sha256(cert_for_hash))

        # ---- Step 3: ECDSA over prehashed H ----
        sig_der = priv_key.sign(H, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(sig_der)

        # set signer=('certificate',[cert_decoded]) and set signature
        wire = encoder.IEEE_spec.Ieee1609Dot2Data.to_coer(IeeeDot2Data)
        encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(wire)
        rt = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

        tbs2  = encoder.IEEE_spec.ToBeSignedData.to_coer(rt["content"][1]["tbsData"])
        #print(rt["content"][1]["signer"])
        cert2 = encoder.IEEE_spec.Certificate.to_coer(rt["content"][1]["signer"][1][0])

        H2 = _sha256(_sha256(tbs2) + _sha256(cert2))
        assert H2 == H, "You signed different bytes than you transmitted"

        if normalize_low_s and s > (_N // 2):
            s = _N - s

        return r, s, priv_key


    def sign_Ieee1609Dot2Data_ISS(self,  IeeeDot2Data, encoder):
            
        api_key = getenv("API_KEY")
        if not api_key: raise Exception("API_KEY env variable not set!")

        tbs_coer = encoder.IEEE_spec.ToBeSignedData.to_coer(IeeeDot2Data['content'][1]['tbsData'])
        headers = {
            "Content-Type": "application/json",
            "x-virtual-api-key": api_key
        }
        payload = {
            "psid": 32,
            "tbsOer": base64.b64encode(tbs_coer).decode("ascii"),
            "jIndex": 2,
            "digestSigner": "false"
            }
        
        sign_response = requests.post("https://api.dm.preprod.v2x.isscms.com/api/v3/virtual-device/sign", headers=headers, json=payload)
        response_json = json.loads(sign_response.text)
        signed_payload = response_json['signedPayload']

        test = base64.b64decode(signed_payload)
        encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(test)
        test = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

        #print(test)

        validation_headers = {
            "Content-Type": "application/json",
            "x-virtual-api-key": api_key
        }
        validation_payload = {"message" : signed_payload, "shouldValidate" : "true" }
        url = "https://api.dm.preprod.v2x.isscms.com/api/v3/virtual-device/validate"
        validation_response = requests.post(url, headers=validation_headers, json=validation_payload)
        validation_response_json = json.loads(validation_response.text)
        if validation_response_json["status"] != "success": raise Exception("Signing failed. Could not validate signature.")

        response_out = validation_response_json["innerPayload"]
        #out = encoder.DSRC_spec.MessageFrame.from_coer(response_out)

        return signed_payload
    
    def validate_signed_data(self, signedData):
        api_key = getenv("API_KEY")
        if not api_key: raise Exception("API_KEY env variable not set!")

        validation_headers = {
            "Content-Type": "application/json",
            "x-virtual-api-key": api_key
        }
        validation_payload = {"message" : signedData, "shouldValidate" : "true" }
        url = "https://api.dm.preprod.v2x.isscms.com/api/v3/virtual-device/validate"
        validation_response = requests.post(url, headers=validation_headers, json=validation_payload)
        validation_response_json = json.loads(validation_response.text)

        if validation_response_json["status"] != "success": raise Exception("Signing failed. Could not validate signature.")

    def time64_us_since_2004(self, dt: datetime.datetime | None = None) -> int:
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int((dt - EPOCH_2004).total_seconds() * 1_000_000)

    
    def inv(self, a): 
        return pow(a, P-2, P)

    def point_add(self, P1, P2):
        if P1 is None: return P2
        if P2 is None: return P1
        x1,y1 = P1; x2,y2 = P2
        if x1 == x2 and (y1 + y2) % P == 0:
            return None
        if P1 == P2:
            lam = (3*x1*x1 + A) * self.inv(2*y1) % P
        else:
            lam = (y2 - y1) * self.inv(x2 - x1) % P
        x3 = (lam*lam - x1 - x2) % P
        y3 = (lam*(x1 - x3) - y1) % P
        return (x3,y3)

    def scalar_mul(self, k, Pnt):
        R = None
        Q = Pnt
        while k:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R

    def decompress_p256(self, x_bytes, y_is_odd):
        x = int.from_bytes(x_bytes, "big")
        y2 = (pow(x, 3, P) + A*x + B) % P
        y = pow(y2, (P + 1) // 4, P)  # p % 4 == 3
        if (y & 1) != int(y_is_odd):
            y = P - y
        return (x, y)

    def Hn_cert(self, cert_coer: bytes) -> int:
        # SEC4 defines Hn; for P-256, using SHA256->int mod n is fine in practice.
        return int.from_bytes(hashlib.sha256(cert_coer).digest(), "big") % N

    def hashed_id8(self, b: bytes) -> bytes:
        return hashlib.sha256(b).digest()[-8:]

    def find_issuer_pub_point(self, trusted_dir: str, issuer_digest8: bytes, encoder):
        td = Path(trusted_dir)
        for f in td.iterdir():
            if not f.is_file():
                continue
            b = f.read_bytes()
            if self.hashed_id8(b) != issuer_digest8:
                continue

            encoder.IEEE_spec.Certificate.from_coer(b)
            issuer = encoder.IEEE_spec.Certificate.get_val()

            # issuer cert likely explicit: verifyKeyIndicator -> verificationKey
            vki = issuer["toBeSigned"]["verifyKeyIndicator"]
            assert vki[0] == "verificationKey"
            form, x_bytes = vki[1]  # e.g. ('compressed-y-0', b'...')
            y_is_odd = (form == "compressed-y-1")
            return self.decompress_p256(x_bytes, y_is_odd)

        raise RuntimeError("Issuer cert not found in trustedcerts (hashedId8 mismatch)")

    def reconstructed_pub_from_implicit(self, cert_coer: bytes, cert_decoded, encoder, trusted_dir: str):
        issuer_digest8 = cert_decoded["issuer"][1]   # 8 bytes
        Qca = self.find_issuer_pub_point(trusted_dir, issuer_digest8, encoder)

        # PU from reconstructionValue
        vki = cert_decoded["toBeSigned"]["verifyKeyIndicator"]
        assert vki[0] == "reconstructionValue"
        form, x_bytes = vki[1]
        y_is_odd = (form == "compressed-y-1")
        Pu = self.decompress_p256(x_bytes, y_is_odd)

        e = self.Hn_cert(cert_coer)
        Qu = self.point_add(self.scalar_mul(e, Pu), Qca)
        return Qu

    def check_key_match(self, cert_coer, cert_decoded, kU, s_int, encoder, trusted_dir):
        Qu = self.reconstructed_pub_from_implicit(cert_coer, cert_decoded, encoder, trusted_dir)

        # Candidate 1: your current formula
        d1 = (kU + s_int) % N
        Q1 = self.scalar_mul(d1, G)

        # Candidate 2: ECQV-style: d = r + e*kU
        e = self.Hn_cert(cert_coer)
        d2 = (s_int + (e * kU) % N) % N
        Q2 = self.scalar_mul(d2, G)

        return (Qu == Q1, Qu == Q2)

    
    def sign_Ieee1609Dot2Data(self, IeeeDot2Data, encoder):
        profile = self.cert_data
        cert_coer = profile["cert_coer"]
        s_bytes   = profile["s_bytes"]
        sk_base   = profile["sk_base"]
        sgn_exp   = profile["sgn_expnsn_bytes"]
        i, j      = profile["iValue"], profile["jValue"]

        # from asn.Ieee1609Dot2_optional_psid import IEEE1609dot2


        # encoder.IEEE_spec = IEEE1609dot2

        # decode cert once
        encoder.IEEE_spec.Certificate.from_coer(cert_coer)
        cert_decoded = encoder.IEEE_spec.Certificate.get_val()

        # 1) Set signer and generationTime ONCE (final values)
        IeeeDot2Data["content"][1]["signer"] = ("certificate", [cert_decoded])

        hdr = IeeeDot2Data["content"][1]["tbsData"]["headerInfo"]
        now_us = self.time64_us_since_2004()
        hdr["generationTime"] = now_us - 500_000  # 0.5s in the past

        # (optional) assert in cert window BEFORE signing
        vp = cert_decoded["toBeSigned"]["validityPeriod"]
        start_sec = vp["start"]
        dur_kind, dur_val = vp["duration"]
        end_sec = start_sec + (dur_val * 3600 if dur_kind == "hours" else dur_val)
        gt_sec = hdr["generationTime"] // 1_000_000
        assert start_sec <= gt_sec <= end_sec

        # 2) Sign (do NOT change any tbsData fields after this)
        r, s, priv_key = self.butterfly_expansion(
            encoder, IeeeDot2Data,
            cert_coer, s_bytes,
            sk_base, sgn_exp,
            i, j,
        )

        IeeeDot2Data["content"][1]["signature"] = (
            "ecdsaNistP256Signature",
            {"rSig": ("x-only", r.to_bytes(32, "big")),
            "sSig": s.to_bytes(32, "big")}
        )

        # validate 
        IeeeDot2Data_coer = encoder.IEEE_spec.Ieee1609Dot2Data.to_coer(IeeeDot2Data)
        if self.validate: self.validate_signed_data(base64.b64encode(IeeeDot2Data_coer).decode("ascii"))

        return IeeeDot2Data