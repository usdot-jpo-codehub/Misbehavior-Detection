# tests/test_signing_localization.py
import hashlib

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def test_embedded_certificate_roundtrip_stable(encoder, signed_ieee_msg_coer):
    """
    If this fails, you are hashing different cert bytes than the verifier uses.

    It decodes the final transmitted message, extracts the embedded leaf cert,
    re-encodes it, and checks stability.
    """
    encoder.IEEE_spec.Ieee1609Dot2Data.from_coer(signed_ieee_msg_coer)
    msg_val = encoder.IEEE_spec.Ieee1609Dot2Data.get_val()

    content_tag, signed_data = msg_val["content"]
    assert content_tag == "signedData"

    signer_tag, signer_list = signed_data["signer"]
    assert signer_tag == "certificate"
    assert len(signer_list) >= 1

    leaf_cert_val = signer_list[0]
    leaf_cert_coer = encoder.IEEE_spec.Certificate.to_coer(leaf_cert_val)

    # Re-decode/re-encode leaf cert
    encoder.IEEE_spec.Certificate.from_coer(leaf_cert_coer)
    leaf_val_2 = encoder.IEEE_spec.Certificate.get_val()
    leaf_cert_coer_2 = encoder.IEEE_spec.Certificate.to_coer(leaf_val_2)

    assert leaf_cert_coer_2 == leaf_cert_coer, (
        "Leaf certificate COER bytes are not stable on round-trip. "
        "Compute h_cert over Certificate.to_coer(leaf_cert_val) (the embedded object), "
        "not over any file bytes you loaded earlier."
    )


def test_signature_rsig_is_x_only(signed_ieee_msg_val):
    """
    Your code currently sets rSig to ('compressed-y-0', ...). For IEEE 1609.2 ECDSA signatures,
    rSig is typically ('x-only', rBytes). If this fails, fix signature packaging first.
    """
    content_tag, signed_data = signed_ieee_msg_val["content"]
    assert content_tag == "signedData"

    sig_type, sig = signed_data["signature"]
    assert sig_type == "ecdsaNistP256Signature"

    r_choice, r_bytes = sig["rSig"]
    assert r_choice == "x-only", f"Expected rSig to be 'x-only', got {r_choice}"
    assert len(r_bytes) == 32
    assert len(sig["sSig"]) == 32