import ctypes 
from gen_utils import asn_TYPE_descriptor_s, ASN_APP_CONSUME, asn_codec_ctx_s


class asn_dec_rval_t(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_int),     # enum asn_dec_rval_code_e
        ("consumed", ctypes.c_size_t),
    ]


def decode(func_name, data, td, lib):
    if hasattr(lib, func_name):
        getattr(lib, func_name).restype = asn_dec_rval_t
        getattr(lib, func_name).argtypes = [
                ctypes.POINTER(asn_codec_ctx_s),
                ctypes.POINTER(asn_TYPE_descriptor_s),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
    else: raise Exception(f"couldn't find {func_name} functiuon in library.")
    
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    out_ptr = ctypes.c_void_p(None)
    rval = getattr(lib, func_name)(None, td, ctypes.byref(out_ptr), ctypes.cast(buf, ctypes.c_void_p), len(data))
    return out_ptr, rval


# ---------------------------
# Decode helper functions
# ---------------------------

def decode_xer(lib, td, data: bytes):
    """
    Decode XER into a newly-allocated C structure.
    Returns (ptr, rval) where ptr is c_void_p to the decoded struct or NULL on fail.
    """
    out_ptr, rval = decode("xer_decode", data, td, lib)
    return out_ptr, rval



def decode_uper(lib, td, data: bytes):
    """
    Decode UPER (uses uper_decode_complete if available, else uper_decode).
    Returns (ptr, rval).
    """

    out_ptr, rval = decode("uper_decode_complete", data, td, lib)
    return out_ptr, rval


def decode_jer(lib, td, data: bytes):
    """
    Decode JER (JSON) text into a newly-allocated C structure.
    Returns (ptr, rval). Requires lib.jer_decode to exist.
    """
    out_ptr, rval = decode("jer_decode", data, td, lib)
    return out_ptr, rval


def decode_oer(lib, td, data: bytes):
    """
    Decode JER (JSON) text into a newly-allocated C structure.
    Returns (ptr, rval). Requires lib.jer_decode to exist.
    """
    out_ptr, rval = decode("oer_decode", data, td, lib)
    return out_ptr, rval