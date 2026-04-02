import base64
import ctypes
import datetime
import hashlib
import hmac as _hmac_mod
import json
import os
import re
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import xmltodict

import decoder_utils
import encoder_utils
import signing_utils
from asn1c_bridge import get_td


class ReportGenerator:
    def __init__(self):
        self.plaintext = {}
        self.signed = {}
        self.sTE = {}
        self.report = {}
        self.report_type = "plaintext"

    def print_report(self):
        print(self.report)

    def debug_report(self):
        now = datetime.datetime.now()
        # Format for filename: YYYYMMDD_HHMMSS
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        open(f"output/mbr-{self.report_type}-{timestamp}.json", "w").write(json.dumps(self.report, indent=4))
        print(f"Wrote mbr-{self.report_type}-{timestamp}.json")

    def encode_report(self):
        lib = ctypes.CDLL("libs/asn1clib.so")
        td = get_td(lib, "SaeJ3287Data")

        data = xmltodict.unparse(self.report, full_document=False)
        # asn1c's XER decoder requires self-closing empty elements (<tag/>) for
        # ENUMERATED and CHOICE types; convert any <tag></tag> residuals from xmltodict.
        data = re.sub(r'<([^/>\s]+)></\1>', r'<\1/>', data)
        data = data.encode('utf-8')
        sptr, rval = decoder_utils.decode_xer(lib, td, data)
        print(f"XER decode: code={rval.code} consumed={rval.consumed}")
        if rval.code != 0:
            raise SystemExit(f"XER decode failed")

        mbr = encoder_utils.encode_oer(lib, td, sptr)
        return mbr

    def _encode_mbr_to_oer(self, mbr_content: dict) -> bytes:
        """XER-encode a SaeJ3287Mbr content dict to OER bytes."""
        lib = ctypes.CDLL("libs/asn1clib.so")
        td = get_td(lib, "SaeJ3287Mbr")
        mbr_xer = xmltodict.unparse({"SaeJ3287Mbr": mbr_content}, full_document=False)
        mbr_xer = re.sub(r'<([^/>\s]+)></\1>', r'<\1/>', mbr_xer)
        sptr, rval = decoder_utils.decode_xer(lib, td, mbr_xer.encode("utf-8"))
        if rval.code != 0:
            raise RuntimeError(f"SaeJ3287Mbr XER decode failed (code={rval.code})")
        return encoder_utils.encode_oer(lib, td, sptr)

    def _build_ste(self, ma_cert_path: str) -> dict:
        # OER-encode inner Ieee1609Dot2Data-Signed
        inner_dict = self.signed["SaeJ3287Data"]["content"]["signed"]
        lib = ctypes.CDLL("libs/asn1clib.so")
        td_1609 = get_td(lib, "Ieee1609Dot2Data")
        inner_xer = xmltodict.unparse({"Ieee1609Dot2Data": inner_dict},
                                      full_document=False)
        inner_xer = re.sub(r'<([^/>\s]+)></\1>', r'<\1/>', inner_xer)
        sptr, rval = decoder_utils.decode_xer(lib, td_1609,
                                              inner_xer.encode("utf-8"))
        if rval.code != 0:
            raise RuntimeError(
                f"Ieee1609Dot2Data-Signed XER decode failed (code={rval.code})")
        signed_1609_bytes = encoder_utils.encode_oer(lib, td_1609, sptr)

        # Load MA cert
        with open(ma_cert_path, "rb") as f:
            ma_cert_bytes = f.read()

        td_cert = get_td(lib, "Certificate")
        sptr_cert, rval = decoder_utils.decode_oer(lib, td_cert, ma_cert_bytes)
        if rval.code != 0:
            raise RuntimeError(
                f"MA Certificate OER decode failed (code={rval.code})")
        ma_cert_xer = encoder_utils.encode_xer(lib, td_cert, sptr_cert).decode()
        ma_cert_dict = xmltodict.parse(ma_cert_xer)["Certificate"]

        # Extract eciesNistP256 encryption public key
        enc_key_b64 = (ma_cert_dict["toBeSigned"]["encryptionKey"]
                       ["publicKey"]["eciesNistP256"])
        if "compressed-y-1" in enc_key_b64:
            ma_enc_compressed = bytes([0x03]) + base64.b64decode(
                enc_key_b64["compressed-y-1"])
        else:
            ma_enc_compressed = bytes([0x02]) + base64.b64decode(
                enc_key_b64["compressed-y-0"])
        ma_enc_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ma_enc_compressed)

        # recipientId = last 8 bytes of P1
        p1 = hashlib.sha256(ma_cert_bytes).digest()
        recip_id = p1[-8:]

        # AES-128-CCM encrypt signed payload
        cek = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        ct_with_tag = AESCCM(cek, tag_length=16).encrypt(
            nonce, signed_1609_bytes, None)

        eph_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph_key.public_key()
        Z = eph_key.exchange(ECDH(), ma_enc_pub)

        # K_enc (16 bytes) || K_mac (32 bytes) 
        K = signing_utils._x963_kdf(Z, 48, p1)
        K_enc, K_mac = K[:16], K[16:48]

        # c = CEK XOR K_enc 
        c = bytes(a ^ b for a, b in zip(cek, K_enc))

        # t = HMAC-SHA-256(K_mac, c)[0:16]
        eph_pub_compressed = eph_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint)
        t = _hmac_mod.new(K_mac, c, hashlib.sha256).digest()[:16]

        v_tag = ("compressed-y-0" if eph_pub_compressed[0] == 0x02
                 else "compressed-y-1")
        v_b64 = base64.b64encode(eph_pub_compressed[1:]).decode()

        return {
            "SaeJ3287Data": {
                "version": 1,
                "content": {
                    "sTE": {
                        "protocolVersion": 3,
                        "content": {
                            "encryptedData": {
                                "recipients": {
                                    "certRecipInfo": {
                                        "recipientId": base64.b64encode(
                                            recip_id).decode(),
                                        "encKey": {
                                            "eciesNistP256": {
                                                "v": {v_tag: v_b64},
                                                "c": base64.b64encode(c).decode(),
                                                "t": base64.b64encode(t).decode(),
                                            }
                                        },
                                    }
                                },
                                "ciphertext": {
                                    "aes128ccm": {
                                        "nonce": base64.b64encode(nonce).decode(),
                                        "ccmCiphertext": base64.b64encode(
                                            ct_with_tag).decode(),
                                    }
                                },
                            }
                        },
                    }
                },
            }
        }

    def _build_signed(self, tai_microseconds: int, target_id: int,
                      observation_id: int, evidence: str,
                      cert_bytes: bytes,
                      signing_key: ec.EllipticCurvePrivateKey) -> dict:
        mbr_content = {
            "generationTime": tai_microseconds,
            "observationLocation": {
                "latitude": 10,
                "longitude": 10,
                "elevation": 10,
            },
            "report": {
                "aid": 32,
                "content": {
                    "AsrBsm": {
                        "observations": {
                            "ObservationsByTarget-Bsm": {
                                "tgtId": target_id,
                                "observations": {
                                    "ANY": f"{observation_id:02x}00"
                                },
                            }
                        },
                        "v2xPduEvidence": {
                            "V2xPduStream": {
                                "type": 2,
                                "v2xPdus": {
                                    "ANY": evidence
                                },
                                "subjectPduIndex": 0,
                            }
                        },
                        "nonV2xPduEvidence": None,
                    }
                },
            },
        }

        mbr_oer = self._encode_mbr_to_oer(mbr_content)
        unsecured_data_b64 = base64.b64encode(mbr_oer).decode("ascii")

        cert_dict = signing_utils.decode_cert_to_xer_dict(cert_bytes)

        tbs_data = {
            "payload": {
                "data": {
                    "protocolVersion": 3,
                    "content": {"unsecuredData": unsecured_data_b64},
                }
            },
            "headerInfo": {
                "psid": 38,
            },
        }
        _lib = ctypes.CDLL("libs/asn1clib.so")
        _td_tbs = get_td(_lib, "ToBeSignedData")
        _tbs_xer = xmltodict.unparse({"ToBeSignedData": tbs_data}, full_document=False)
        _tbs_xer = re.sub(r'<([^/>\s]+)></\1>', r'<\1/>', _tbs_xer)
        _tbs_sptr, _tbs_rval = decoder_utils.decode_xer(_lib, _td_tbs, _tbs_xer.encode("utf-8"))
        if _tbs_rval.code != 0:
            raise RuntimeError(f"ToBeSignedData XER decode failed (code={_tbs_rval.code})")
        tbs_coer = encoder_utils.encode_oer(_lib, _td_tbs, _tbs_sptr)

        # Sign SHA-256(SHA-256(COER(tbsData)) || SHA-256(COER(cert)))
        _msg = signing_utils._1609_data_signing_hash(cert_bytes, tbs_coer)
        _r_int, _s_int = signing_utils._sign_digest(signing_key, _msg)
        r_b64 = base64.b64encode(_r_int.to_bytes(32, "big")).decode("ascii")
        s_b64 = base64.b64encode(_s_int.to_bytes(32, "big")).decode("ascii")

        return {
            "SaeJ3287Data": {
                "version": 1,
                "content": {
                    "signed": {
                        "protocolVersion": 3,
                        "content": {
                            "signedData": {
                                "hashId": {"sha256": None},
                                "tbsData": {
                                    "payload": {
                                        "data": {
                                            "protocolVersion": 3,
                                            "content": {
                                                "unsecuredData": unsecured_data_b64
                                            },
                                        }
                                    },
                                    "headerInfo": {
                                        "psid": 38,
                                    },
                                },
                                "signer": {
                                    "certificate": {"Certificate": cert_dict}
                                },
                                "signature": {
                                    "ecdsaNistP256Signature": {
                                        "rSig": {"x-only": r_b64},
                                        "sSig": s_b64,
                                    }
                                },
                            }
                        },
                    }
                },
            }
        }

    def generate_report(self, target_id, observation_id, evidence, cert_bytes, signing_key, ma_cert_path: str = None):
        # generationTime = number of (TAI) microseconds since 00:00:00 UTC, 1 January, 2004
        start_date = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
        current_date = datetime.datetime.now(tz=datetime.timezone.utc)
        time_difference = current_date - start_date
        leap_seconds = 5
        total_tai_seconds = time_difference.total_seconds() + leap_seconds
        tai_microseconds = int(total_tai_seconds * 1_000_000)

        observation = ""

        if target_id == 5:
            observation = "ValueTooLarge"
        elif target_id == 2:
            if observation_id == 1:
                observation = "Security-MessageIdIncWithHeaderInfo"
            elif observation_id == 2:
                observation = "Security-HeaderIncWithSecurityProfile"
            elif observation_id == 3:
                observation = "Security-HeaderPsidIncWithCertificate"
            elif observation_id == 4:
                observation = "Security-MessageIncWithSsp"
            elif observation_id == 5:
                observation = "Security-HeaderTimeOutsideCertificateValidity"
            elif observation_id == 6:
                observation = "Security-MessageLocationOutsideCertificateValidity"
            elif observation_id == 7:
                observation = "Security-HeaderLocationOutsideCertificateValidity"

        self.plaintext = {
            "SaeJ3287Data": {
                "version": 1,
                "content": {
                    "plaintext": {
                        "generationTime": tai_microseconds,
                        "observationLocation": {
                            "latitude": 10,
                            "longitude": 10,
                            "elevation": 10,
                        },
                        "report": {
                            "aid": 32,
                            "content": {
                                "AsrBsm": {
                                    "observations": {
                                        "ObservationsByTarget-Bsm": {
                                            "tgtId": target_id,
                                            "observations": {
                                                "ANY": f"{observation_id:02x}00"
                                            }
                                        }
                                    },
                                    "v2xPduEvidence": {
                                        "V2xPduStream": {
                                            "type": 2,
                                            "v2xPdus": {
                                                "ANY": evidence
                                            },
                                            "subjectPduIndex": 0,
                                        }
                                    },
                                    "nonV2xPduEvidence": None
                                }
                            }
                        }
                    }
                }
            }
        }

        if ma_cert_path is not None:
            self.report_type = "sTE"
            self.signed = self._build_signed(
                tai_microseconds, target_id, observation_id, evidence, cert_bytes, signing_key
            )
            self.sTE = self._build_ste(ma_cert_path)
            self.report = self.sTE
        elif cert_bytes is not None:
            self.report_type = "signed"
            self.signed = self._build_signed(
                tai_microseconds, target_id, observation_id, evidence, cert_bytes, signing_key
            )
            self.report = self.signed
        else:
            self.report_type = "plaintext"
            self.report = self.plaintext

        mbr = self.encode_report()

        return mbr