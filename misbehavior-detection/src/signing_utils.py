import ctypes
import datetime
import glob
import hashlib
import json
import os
import pathlib
import re
import struct
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import xmltodict

import decoder_utils
import encoder_utils
from gen_utils import get_td

def load_signing_key(path: str, bundle_dir: str = None):
    """Load the actual P-256 signing key for an ISS SCMS application certificate.

    ISS SCMS issues implicit (ECQV) application certificates per IEEE 1609.2.

    For RSU bundles (rsu-N/downloadFiles/<hash>.s):
      bundle_dir defaults to the rsu-N/ directory (one level above downloadFiles/).

    For pseudonym bundles (download/{i}/{i}_{j}.s):
      bundle_dir must be passed explicitly (the root of the pseudonym bundle).
      Butterfly expansion is applied when sgn_expnsn.key is present at bundle_dir.

    ECQV key reconstruction (IEEE 1609.2 §5.3.2 / SCMS profile):
      tbs_coer  = COER(cert.toBeSigned)
      e         = SHA-256( SHA-256(tbs_coer) || SHA-256(issuer_cert_coer) )  mod n
      kU        = (sk_base + f_k(i, j))  mod n      [butterfly; else kU = sk_base]
      dU        = (r + e * kU)  mod n

    path is expected to be the .s file.
    Falls back to PEM if path does not point to a 32-byte raw scalar.
    """
    # P-256 curve order
    _N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) == 32:
        r = int.from_bytes(data, 'big')

        # Locate bundle_dir (contains dwnl_sgn.priv, certchain/, trustedcerts/)
        if bundle_dir is None:
            # RSU layout: dwnl_sgn.priv lives one level above downloadFiles/
            bundle_dir = os.path.dirname(os.path.dirname(path))
        seed_path = os.path.join(bundle_dir, 'dwnl_sgn.priv')
        with open(seed_path, 'rb') as f:
            sk_base = int.from_bytes(f.read(), 'big')

        # Load corresponding cert
        cert_path = path[:-2] + '.cert'
        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()

        # Butterfly expansion when sgn_expnsn.key is present (pseudonym bundle)
        exp_path = os.path.join(bundle_dir, 'sgn_expnsn.key')
        if os.path.exists(exp_path):
            with open(exp_path, 'rb') as f:
                sgn_expnsn = f.read()
            # i and j are hex values encoded in the filename: {i}_{j}.cert
            basename = os.path.splitext(os.path.basename(cert_path))[0]
            parts = basename.split('_')
            i_val = int(parts[0], 16)
            j_val = int(parts[1], 16)
            f_ij = _expansion_scalar_aes_dm(sgn_expnsn, i_val, j_val, _N)
            kU = (sk_base + f_ij) % _N
        else:
            kU = sk_base

        # e: SHA-256( SHA-256(COER(TBS)) || SHA-256(issuer_cert) ) mod n
        _cert_lib = ctypes.CDLL(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'libs', 'Certificate.so'))
        _cert_td = get_td(_cert_lib, 'Certificate')
        _sptr, _rval = decoder_utils.decode_oer(_cert_lib, _cert_td, cert_bytes)
        cert_jer = encoder_utils.encode_jer(_cert_lib, _cert_td, _sptr)
        cert_dict = json.loads(cert_jer)
        _tbs_td = get_td(_cert_lib, 'ToBeSignedCertificate')
        _tbs_jer = json.dumps(cert_dict['toBeSigned']).encode()
        _tbs_sptr, _tbs_rval = decoder_utils.decode_jer(_cert_lib, _tbs_td, _tbs_jer)
        tbs_coer = encoder_utils.encode_oer(_cert_lib, _tbs_td, _tbs_sptr)
        issuer_info = cert_dict.get("issuer", {})
        issuer_hid8_hex = (issuer_info.get("sha256AndDigest")
                           or issuer_info.get("sha384AndDigest"))
        if issuer_hid8_hex:
            try:
                issuer_cert_coer = _find_issuer_cert_coer(
                    bundle_dir, bytes.fromhex(issuer_hid8_hex))
                e = int.from_bytes(
                    hashlib.sha256(
                        hashlib.sha256(tbs_coer).digest() +
                        hashlib.sha256(issuer_cert_coer).digest()
                    ).digest(), 'big'
                ) % _N
            except RuntimeError as exc:
                print(f"  WARNING: {exc}; falling back to SHA256(cert) for e",
                      file=sys.stderr)
                e = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big') % _N
        else:
            e = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big') % _N

        scalar = (r + (e * kU) % _N) % _N
        return ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())

    return serialization.load_pem_private_key(data, password=None,
                                               backend=default_backend())


def select_pseudonym_cert(certs_dir: str):
    """Scan download/{i}/{i}_{j}.cert under certs_dir and return (cert_path, key_path)
    for the currently valid certificate with the earliest expiry.
    Exits with an error if no valid certificate is found.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    candidates = []
    for cert_path in sorted(glob.glob(
            os.path.join(certs_dir, 'download', '*', '*.cert'))):
        key_path = cert_path[:-5] + '.s'
        if not os.path.exists(key_path):
            continue
        try:
            with open(cert_path, 'rb') as fh:
                start, expire = parse_cert_validity(fh.read())
        except ValueError:
            continue
        if start <= now < expire:
            candidates.append((expire, cert_path, key_path))
    if not candidates:
        print(f"ERROR: no valid pseudonym certificate found under {certs_dir}/download/ "
              f"(current UTC time: {now.strftime('%Y-%m-%d %H:%M:%S')})",
              file=sys.stderr)
        for cert_path in sorted(glob.glob(
                os.path.join(certs_dir, 'download', '*', '*.cert'))):
            try:
                with open(cert_path, 'rb') as fh:
                    start, expire = parse_cert_validity(fh.read())
                status = "not yet valid" if now < start else "expired"
                print(f"  {cert_path}: {start.strftime('%Y-%m-%d %H:%M')} – "
                      f"{expire.strftime('%Y-%m-%d %H:%M')} UTC  [{status}]",
                      file=sys.stderr)
            except ValueError:
                print(f"  {cert_path}: could not parse validity period",
                      file=sys.stderr)
        sys.exit(1)
    candidates.sort()
    _, cert_path, key_path = candidates[0]
    return cert_path, key_path


def select_rsu_cert(certs_dir: str):
    """Scan rsu-*/downloadFiles/*.cert under certs_dir and return (cert_path, key_path)
    for the currently valid certificate with the earliest expiry.
    Exits with an error if no valid certificate is found.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    candidates = []
    for cert_path in sorted(glob.glob(
            os.path.join(certs_dir, 'rsu-*/downloadFiles/*.cert'))):
        key_path = cert_path[:-5] + '.s'
        if not os.path.exists(key_path):
            continue
        try:
            with open(cert_path, 'rb') as fh:
                start, expire = parse_cert_validity(fh.read())
        except ValueError:
            continue
        if start <= now < expire:
            candidates.append((expire, cert_path, key_path))
    if not candidates:
        print(f"ERROR: no valid RSU certificate found under {certs_dir} "
              f"(current UTC time: {now.strftime('%Y-%m-%d %H:%M:%S')})",
              file=sys.stderr)
        # Print all certs found with their validity windows to aid diagnosis
        for cert_path in sorted(glob.glob(
                os.path.join(certs_dir, 'rsu-*/downloadFiles/*.cert'))):
            try:
                with open(cert_path, 'rb') as fh:
                    start, expire = parse_cert_validity(fh.read())
                status = "not yet valid" if now < start else "expired"
                print(f"  {cert_path}: {start.strftime('%Y-%m-%d %H:%M')} – "
                      f"{expire.strftime('%Y-%m-%d %H:%M')} UTC  [{status}]",
                      file=sys.stderr)
            except ValueError:
                print(f"  {cert_path}: could not parse validity period",
                      file=sys.stderr)
        sys.exit(1)
    candidates.sort()
    _, cert_path, key_path = candidates[0]
    return cert_path, key_path


def parse_cert_validity(cert_bytes: bytes):
    """Parse (start, expire) as UTC datetimes from an IEEE 1609.2 cert.

    Scans for a ValidityPeriod: Time32 (4 bytes) followed by a Duration
    CHOICE tag (0x80–0x86) and Uint16 value.  Collects all plausible matches
    (start in 2015–2040 range, duration >= 1 hour) and returns the one with
    the latest start — avoiding false positives from incidental byte patterns
    elsewhere in the cert with very short durations.
    """
    EPOCH = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
    DURATION_SECS = {0: 1e-6, 1: 1e-3, 2: 1, 3: 60, 4: 3600, 5: 216000, 6: 365.25 * 86400}
    lo = datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc)
    hi = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
    candidates = []
    for i in range(len(cert_bytes) - 6):
        tag = cert_bytes[i + 4]
        if 0x80 <= tag <= 0x86:
            t = struct.unpack_from('>I', cert_bytes, i)[0]
            start = EPOCH + datetime.timedelta(seconds=t)
            if lo <= start <= hi:
                alt = tag & 0x07
                val = struct.unpack_from('>H', cert_bytes, i + 5)[0]
                secs = val * DURATION_SECS[alt]
                if secs >= 3600:  # ignore durations shorter than 1 hour (false positives)
                    try:
                        expire = start + datetime.timedelta(seconds=secs)
                    except OverflowError:
                        continue
                    candidates.append((start, expire))
    if not candidates:
        raise ValueError("Could not parse validity period from certificate")
    return max(candidates, key=lambda x: x[0])  # latest start


def _find_issuer_cert_coer(bundle_dir: str, issuer_hid8: bytes) -> bytes:
    """Scan trustedcerts/ and certchain/ for the cert whose SHA-256[-8:] matches issuer_hid8."""
    for subdir in ("trustedcerts", "certchain"):
        root = pathlib.Path(bundle_dir) / subdir
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            b = p.read_bytes()
            if hashlib.sha256(b).digest()[-8:] == issuer_hid8:
                return b
    raise RuntimeError(f"Issuer cert not found for HashedId8={issuer_hid8.hex()}")


def _expansion_scalar_aes_dm(seed_key: bytes, i: int, j: int, order_n: int) -> int:
    """AES-ECB butterfly key expansion KDF (SCMS pseudonym cert profile).

    Computes f_k(i, j) mod N for butterfly key expansion:
        kU = (sk_base + f_k(i, j)) mod N

    Algorithm matches DataSigner.expansion_scalar_aes_dm() in faulty-bsm-generator.
    """
    if len(seed_key) not in (16, 24, 32):
        raise ValueError("seed_key must be 16/24/32 bytes for AES")

    x_int = ((i & 0xFFFFFFFF) << 64) | ((j & 0xFFFFFFFF) << 32)
    x = x_int.to_bytes(16, "big")

    blocks = []
    for t in (1, 2, 3):
        xt = (int.from_bytes(x, "big") + t) & ((1 << 128) - 1)
        xt_bytes = xt.to_bytes(16, "big")
        cipher = Cipher(algorithms.AES(seed_key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(xt_bytes) + enc.finalize()
        blocks.append(bytes(a ^ b for a, b in zip(ct, xt_bytes)))

    return int.from_bytes(b"".join(blocks), "big") % order_n


def _sign_digest(signing_key, msg: bytes) -> tuple:
    """ECDSA-P256/SHA-256 sign *msg*. Returns (r_int, s_int).

    For IEEE 1609.2 data signing, pass the 64-byte preimage returned by
    _1609_data_signing_hash() so that the final digest is
    SHA-256(SHA-256(tbsData) || SHA-256(cert)).
    """
    sig_der = signing_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return decode_dss_signature(sig_der)


def _1609_data_signing_hash(cert_bytes: bytes, tbs_bytes: bytes) -> bytes:
    """IEEE 1609.2 data signing preimage (§5.3.1.2.2).

    Returns the 64-byte message SHA-256(tbsData) || SHA-256(cert) that is
    passed to _sign_digest(), which then applies one final SHA-256 via ECDSA,
    yielding the effective digest SHA-256(SHA-256(tbsData) || SHA-256(cert)).
    """
    return hashlib.sha256(tbs_bytes).digest() + hashlib.sha256(cert_bytes).digest()


def decode_cert_to_xer_dict(cert_bytes: bytes) -> dict:
    """OER-decode an IEEE 1609.2 Certificate and return its XER representation
    as a dict (compatible with xmltodict / XER workflow).
    """
    lib = ctypes.CDLL("libs/asn1clib.so")
    td = get_td(lib, "Certificate")
    sptr, rval = decoder_utils.decode_oer(lib, td, cert_bytes)
    if rval.code != 0:
        raise RuntimeError(f"Certificate OER decode failed (code={rval.code})")
    cert_xer = encoder_utils.encode_xer(lib, td, sptr)
    cert_xer_str = re.sub(r'<([^/>\s]+)></\1>', r'<\1/>', cert_xer.decode())
    return xmltodict.parse(cert_xer_str).get("Certificate", {})


def _x963_kdf(z: bytes, length: int, p1: bytes = b'') -> bytes:
    """ANSI X9.63 KDF2 with SHA-256 (IEEE 1609.2 §5.3.5.1).

    K = SHA-256(Z || counter || P1) with counter starting at 1.
    For certRecipInfo, P1 = SHA-256(COER(recipient_cert)).
    """
    out = b''
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(z + struct.pack('>I', counter) + p1).digest()
        counter += 1
    return out[:length]