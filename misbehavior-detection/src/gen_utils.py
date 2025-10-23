import ctypes


ASN_APP_CONSUME = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)

class asn_TYPE_descriptor_s(ctypes.Structure):
    """Opaque; we never dereference fields from Python."""
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("xml_tag", ctypes.c_char_p)
    ]

class asn_codec_ctx_s(ctypes.Structure):
    """We pass NULL, so we don't need fields here."""
    _fields_ = []
    

def get_td(lib, base_name: str):
    """
    Return a POINTER(asn_TYPE_descriptor_s) to the *object* asn_DEF_<base_name>.
    This works when the symbol is a struct object (the common asn1c case).
    """
    import ctypes
    from ctypes import POINTER, c_char

    sym = f"asn_DEF_{base_name}"

    # Get the symbol's address itself (not its contents).
    # This treats the symbol as a 1-byte blob so ctypes will give us its address.
    blob = (c_char * 1).in_dll(lib, sym)
    addr = ctypes.addressof(blob)

    # Cast the symbol address to a pointer to the descriptor struct.
    return ctypes.cast(addr, POINTER(asn_TYPE_descriptor_s))