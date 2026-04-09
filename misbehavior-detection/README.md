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

1. If **`lib/asn1clib.so`, `lib/Certificate.so` and `lib/MessageFrame.so` are not already present**, generate shared library for SAE J3287 ASN.1 following instructions in above section.
2. Provide a COER-encoded IEEE1609Dot2Data file in `data/Ieee1609Dot2Data/`. This file should encompass a faulty (misbehaving) BSM. `Ieee1609Dot2Data_bad_accel.coer` has been provided for your convenience. This file contains a BSM with an acceleration exceeding the range allowed by the J3287 ASN.1 schema.
3. Run detection:
```
python3 src/detection.py --misbehaviors acceleration-ValueOutofRange --bsm data/Ieee1609Dot2Data/{filename}
```
1. Reports will be generated to `output/` directory

Use `--debug` to emit JSON snapshots of the internal report structure.


## Command-Line Arguments

Primary usage:

```bash
python3 src/detection.py [options]
```

| Flag | Short Form | Required | Default | Description |
|---|---|---|---|---|
| `--misbehaviors` | `-m` | No | `acceleration-ValueOutofRange` | Space-separated list of one or more misbehavior checks to run. |
| `--bsm` | `-b` | No | `data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer` | Path to a single `.coer` BSM file or to a directory containing multiple `.coer` files. |
| `--certs-dir` | `-c` | No | None | Path to an SCMS certificate bundle used to sign generated reports. Supports pseudonym bundles with a `download/` layout and RSU bundles with an `rsu-*/downloadFiles/` layout. |
| `--ma-key` | None | No | None | Path to the Misbehavior Authority recipient certificate. Use this together with `--certs-dir` when generating an sTE-wrapped report instead of a plaintext or signed-only report. |
| `--debug` | `-d` | No | Disabled | Prints the internal report representation as JER/JSON for inspection while still writing encoded output files to `output/`. |

### Flag Usage Notes

- `--misbehaviors` accepts multiple values separated by spaces, for example: `--misbehaviors acceleration-ValueOutofRange security-HeaderPsidIncWithCertificate`
- `--bsm` can target either one file or an entire directory. When a directory is provided, every `.coer` file in that directory is processed.
- If `--certs-dir` is omitted, reports will be generated as plaintext.
- If `--certs-dir` is included, but `--ma-key` is omitted, reports will be generated as signed but not encrypted.

### Example Commands

Run the default acceleration check against one input file:

```bash
python3 src/detection.py --bsm data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer
```

Generate signed reports using an SCMS bundle:

```bash
python3 src/detection.py \
	--misbehaviors acceleration-ValueOutofRange \
	--bsm data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer \
	--certs-dir path/to/scms-bundle
```

Generate an sTE-wrapped report for a Misbehavior Authority recipient:

```bash
python3 src/detection.py \
	--misbehaviors acceleration-ValueOutofRange \
	--bsm data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer \
	--certs-dir path/to/scms-bundle \
	--ma-key path/to/ma_public_key.cert
```

## Certificate Bundle Structures

### OBU (Pseudonym) Certificate Bundle

Detected automatically when a `download/` subdirectory is present under `--certs-dir`.

```
<certs-dir>/
├── certchain/
├── download/
├── trustedcerts/         
├── dwnl_enc.priv             
├── dwnl_sgn.priv
├── enc_expnsn.key
├── enr_sign.prv
├── sgn_expnsn.key              
```

### RSU Certificate Bundle

Detected automatically when no `download/` subdirectory is present under `--certs-dir`.

```
<certs-dir>/
└── rsu-{N}/
    ├── certchain/        
    ├── downloadFiles/          
    └── trustedcerts/  
	└── dwnl_enc.priv  
	└── dwnl_sgn.priv  
	└── enr_sign.prv       
```

- Multiple `rsu-{N}/` subdirectories may be present; the currently valid certificate with the earliest expiry is selected automatically.

## Obtaining the MA Certificate from an RA (IEEE 1609.2.1 §6.3.5.13)

IEEE 1609.2.1-2022 §6.3.5.13 defines a standard REST endpoint for downloading the MA certificate:

```
GET https://{ra-host}/v3/ma-certificate?psid={hex-psid}
```

where `{hex-psid}` is the minimal-length hex encoding of the PSID for the application being reported (e.g. `20` for BSM, PSID 32 = 0x20).

**Example (ISS pre-production RA):**

```bash
curl "https://ra.preprod.v2x.isscms.com/v3/ma-certificate?psid=20" \
    -o certs/ma_keys/iss_ma_public_key.cert
```

The response body is the raw COER-encoded `Certificate` (binary, `application/octet-stream`).


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
