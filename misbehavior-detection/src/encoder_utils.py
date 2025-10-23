import ctypes
from gen_utils import asn_TYPE_descriptor_s, ASN_APP_CONSUME


class asn_enc_rval_t(ctypes.Structure):
    _fields_ = [
        ("encoded", ctypes.c_ssize_t),                 # <0 on failure
        ("failed_type", ctypes.POINTER(asn_TYPE_descriptor_s)),
        ("failed_struct", ctypes.c_void_p),
    ]

# ---------------------------
# Encode helpers
# ---------------------------

def _collect_bytes():
    chunks = []

    @ASN_APP_CONSUME
    def cb(buf_ptr, sz, key):
        if buf_ptr and sz:
            # Copy sz bytes from buf_ptr
            bs = ctypes.string_at(buf_ptr, sz)
            chunks.append(bs)
        return 0  # 0 = success; non-zero stops encode
    return cb, chunks


def encode(func_name, sptr, flags, td, lib):
    if hasattr(lib, func_name):
        getattr(lib, func_name).restype = asn_enc_rval_t
        getattr(lib, func_name).argtypes = [
            ctypes.POINTER(asn_TYPE_descriptor_s),  # td
            ctypes.c_void_p,                        # const asn_per_constraints_t *constraints (NULL ok)
            ctypes.c_int,                           # sptr
            ASN_APP_CONSUME,                        # buffer
            ctypes.c_void_p,                        # buflen
        ]
    
    cb, chunks = _collect_bytes()
    rv = getattr(lib, func_name)(td, sptr, flags, cb, None)

    if rv.encoded < 0:
        raise RuntimeError(f"encoding with {func_name} failed")
    return b"".join(chunks)


def encode_xer(lib, td, sptr, flags: int = 0) -> bytes:
    """
    Encode to XER text. Returns bytes.
    """
    return encode("xer_encode", sptr, flags, td, lib)


def encode_uper(lib, td, sptr, max_bytes: int = 4096) -> bytes:
    """
    Encode to UPER using uper_encode_to_buffer, if present.
    """
    if not hasattr(lib, "uper_encode_to_buffer"):
        raise RuntimeError("uper_encode_to_buffer not found in library")

    lib.uper_encode.restype = asn_enc_rval_t
    lib.uper_encode.argtypes = [
        ctypes.POINTER(asn_TYPE_descriptor_s),  # td
        ctypes.c_void_p,                        # constraints (NULL ok)
        ctypes.c_void_p,                        # sptr
        ASN_APP_CONSUME,                        # consume_bytes_cb
        ctypes.c_void_p,                        # app_key
    ]

    cb, chunks = _collect_bytes()
    rv = lib.uper_encode(td, None, sptr, cb, None)

    if rv.encoded < 0:
        print(rv.encoded)
        print(rv.failed_type.contents.name)
        raise RuntimeError("uper_encode failed")

    # rv.encoded is bit length; trim to full bytes
    nbytes = (rv.encoded + 7) // 8
    data = b"".join(chunks)
    return data[:nbytes]

def encode_jer(lib, td, sptr, flags: int = 0) -> bytes:
    """
    Encode to JER (JSON) text. Returns bytes.
    """
    return encode("jer_encode", sptr, flags, td, lib)


def encode_oer(lib, td, sptr) -> bytes:
    """
    Encode to OER (Octet Encoding Rules) form. Returns bytes.
    """
    lib.oer_encode.restype = asn_enc_rval_t
    lib.oer_encode.argtypes = [
        ctypes.POINTER(asn_TYPE_descriptor_s),  # td
        ctypes.c_void_p,                        # sptr
        ASN_APP_CONSUME,                        # buffer
        ctypes.c_void_p,                        # buflen
    ]
    
    cb, chunks = _collect_bytes()
    rv = lib.oer_encode(td, sptr, cb, None)
    if rv.encoded < 0:
        print(rv.encoded)
        print(rv.failed_type.contents.name)
        raise RuntimeError(f"encoding with oer_encode failed")
    return b"".join(chunks)