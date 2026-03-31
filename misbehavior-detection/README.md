# Misbehavior Detection and Reporting Tool

Open-source Python tool built using asn1c and ctypes for analyzing Basic Safety Messages (BSM) for misbehaviors and generating misbehavior reports.


## Directory Layout

```
libs/                 # Compiled asn1c shared libraries 
data/<PDU>/           # Sample encoded inputs (PER, OER, XER, JER)
output/               # Generated conversions & reports
src/                  # Detection and generation logic
```

## Prerequisites

Install Python dependencies:

```bash
pip install -r requirements.txt
```


## Building ASN.1 Shared Libraries

**All required libraries to run this tool are included in this repository.** However, if you would like to build your own libraries, you may do so with the following instructions. 

Note: ASN.1 definition modifications removing parameterization may be required for compatibility with asn1c library.

1. Install open-source asn1c library from: https://github.com/mouse07410/asn1c.
2. Generate C files from ASN.1 using asn1c (adjust skeleton path):
```
asn1c -fcompound-names -S ../asn1c/skeletons ../YOUR_ASN_DIR/*.asn
```
3. Compile to shared object:
```
gcc -I ../asn1c/skeletons/ -fPIC -shared -o {LIB_NAME}.so *.c
```
4. Place `.so` in `libs/`.


## Misbehavior Detection Workflow

1. If **`lib/asn1clib.so` and `lib/MessageFrame.so` are not already present**, generate shared library for SAE J3287 ASN.1 following instructions in above section.
2. Provide a COER-encoded IEEE1609Dot2Data file in `data/Ieee1609Dot2Data/`. This file should encompass a faulty (misbehaving) BSM. `Ieee1609Dot2Data_bad_accel.coer` has been provided for your convenience. This file contains a BSM with an acceleration exceeding the range allowed by the J3287 ASN.1 schema.
3. Run detection:
```
python3 src/detection.py --misbehaviors acceleration-ValueOutofRange --bsm data/Ieee1609Dot2Data/{filename}
```
4. Reports will be generated to `output/` directory

Use `--debug` to emit JSON snapshots of the internal report structure.

## Supported Misbehaviors 

This tool currently supports detection and reporting of all SAE J3287-specified misbehavior types. See [src/misbehaviors/README.md](src/misbehaviors/README.md) for more information.

### `--misbehaviors` Flag Options

| Flag Value | Description |
|---|---|
| `acceleration-ValueOutofRange` | Acceleration value is outside the valid range |
| `security-HeaderIncWithSecurityProfile` | Security header is inconsistent with the security profile |
| `security-HeaderLocationOutsideCertificateValidity` | Security header location is outside the certificate's validity region |
| `security-HeaderPsidIncWithCertificate` | Security header PSID is inconsistent with the certificate |
| `security-HeaderTimeOutsideCertificateValidity` | Security header timestamp is outside the certificate's validity period |
| `security-MessageIdIncWithHeaderInfo` | Security message ID is inconsistent with the header info |
| `security-MessageIncWithSsp` | Security message is inconsistent with the SSP (Service Specific Permissions) |
| `security-MessageLocationOutsideCertificateValidity` | Security message location is outside the certificate's validity region |

## Limitations

Currently the code does not support signing and encryption of the MBR. These capabilities will be supported in the next release.
