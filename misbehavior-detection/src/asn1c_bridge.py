#!/usr/bin/env python3

"""
Minimal ctypes bridge for asn1c types (MessageFrame_t example).

What you need first
-------------------
1) Build your asn1c code into a shared library, e.g.:
   gcc -fPIC -shared -o libj2735.so *.c -lm

   Place this in libs and rename to the intended PDU (MesageFrame, Certificate, etc.)


What this exposes
-----------------
- load_lib(path) -> CDLL
- get_td(lib, "MessageFrame") -> POINTER(asn_TYPE_descriptor_s)
- decode_xer(lib, td, data: bytes) -> (ptr: c_void_p, rval: asn_dec_rval_t)
- encode_xer(lib, td, sptr) -> bytes
- decode_uper(lib, td, data: bytes) -> (ptr: c_void_p, rval: asn_dec_rval_t)   [if available]
- encode_uper(lib, td, sptr, max_bytes=4096) -> bytes                          [if available]
- asn_free(lib, td, sptr) -> None (calls asn_struct_free if exported)

Notes
-----
- We pass NULL for `asn_codec_ctx_s*` (default decode context).
- We treat `asn_TYPE_descriptor_s` as opaque; we only pass pointers to it.
- For XER encode, we use the callback-based API to collect bytes.
- UPER encode uses `uper_encode_to_buffer` if present.
- Freeing: we try to call `asn_struct_free(td, ptr)` if your runtime exports it.
  If your runtime does not export it, compile this tiny C helper into your .so:

    // asn_free_shim.c
    #include "asn_application.h"
    void asn_struct_free_shim(const asn_TYPE_descriptor_t *td, void *sptr) {
        if (td && sptr) td->free_struct(td, sptr, 0);
    }

  and then this Python bridge will call `asn_struct_free_shim`.

"""
import ctypes
from ctypes import c_void_p, c_size_t, c_ssize_t, c_int, POINTER, byref
import encoder_utils, decoder_utils
from gen_utils import get_td


# Decode return code enum (common across skeletons)
RC_OK, RC_WMORE, RC_FAIL = 0, 1, 2



# XER output callback: int (*cb)(const void *buffer, size_t size, void *app_key)
ASN_APP_CONSUME = ctypes.CFUNCTYPE(c_int, c_void_p, c_size_t, c_void_p)

# ---------------------------
# Library loader & symbol helpers
# ---------------------------

def load_lib(path):
    lib = ctypes.CDLL(path)
    return lib



# ---------------------------
# Free helper
# ---------------------------

def asn_free(lib, td, sptr):
    """
    Free a structure allocated by asn1c decode.
    Tries: asn_struct_free(td, sptr) or asn_struct_free_shim(td, sptr).
    """
    if sptr is None or int(ctypes.cast(sptr, c_void_p).value or 0) == 0:
        return
    if hasattr(lib, "asn_struct_free"):
        lib.asn_struct_free(td, sptr)
        return
    if hasattr(lib, "asn_struct_free_shim"):
        lib.asn_struct_free_shim(td, sptr)
        return
    # Last resort: leak with a warning (avoid calling libc.free on nested allocations).
    import warnings
    warnings.warn("No asn_struct_free exported; consider adding asn_struct_free_shim to your library.")

# ---------------------------
# Example usage (script mode)
# ---------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", default="Ieee1609Dot2Data", help="library containing PDU (default: MessageFrame)")
    ap.add_argument("--pdu", default="Ieee1609Dot2Data", help="PDU base name (default: MessageFrame)")
    ap.add_argument("--in_codec", default="per", help="codec of input file")
    ap.add_argument("--out_codec", default="xer", help="codec to convert input file to")
    ap.add_argument("--input_file", default="sample-Ieee1609Dot2Data-1.coer", help="file to convert")
    ap.add_argument("--output_name", default="output_example", help="file to convert")
    args = ap.parse_args()

    lib = load_lib(f"libs/{args.lib}.so")
    td = get_td(lib, args.pdu)

    """ read bytes """
    file_path = f"data/{args.pdu}/{args.input_file}"
    data = open(file_path, "rb").read()

    """ decode file """
    decode_func, in_codec = None, None
    if args.in_codec == 'per': decode_func, in_codec = decoder_utils.decode_uper, "UPER"
    elif args.in_codec == 'jer': decode_func, in_codec = decoder_utils.decode_jer, "JER"
    elif args.in_codec == 'xer': decode_func, in_codec = decoder_utils.decode_xer, "XER"
    elif args.in_codec == 'coer': decode_func, in_codec = decoder_utils.decode_oer, "OER"

    # decode using the selected function and codec
    if decode_func is None: raise SystemExit(f"{args.in_codec} not in supported codecs.")
    sptr, rval = decode_func(lib, td, data)
    print(f"{in_codec} decode: code={rval.code} consumed={rval.consumed}")
    if rval.code != RC_OK:
        raise SystemExit(f"{in_codec} decode failed")


    """ encode out """
    encode_func, out_codec, extension = None, None, None
    if args.out_codec == 'per': encode_func, out_codec, ext = encoder_utils.encode_uper, "UPER", "per"
    if args.out_codec == 'jer': encode_func, out_codec, ext = encoder_utils.encode_jer, "JER", "json"
    if args.out_codec == 'xer': encode_func, out_codec, ext = encoder_utils.encode_xer, "XER", "xml"
    if args.out_codec == 'coer': encode_func, out_codec, ext = encoder_utils.encode_oer, "OER", "coer"

    out = encode_func(lib, td, sptr)
    open(f"output/{args.output_name}_{args.pdu}.{ext}", "wb").write(out)
    print(f"Wrote {out_codec}: {len(out)} bytes -> {args.output_name}")

    # free asn structs in memory
    asn_free(lib, td, sptr)