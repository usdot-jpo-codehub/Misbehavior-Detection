# Misbehavior Detection and Reporting Tool

Open-source Python tool built using asn1c and ctypes for analyzing Basic Safety Messages (BSMs) for misbehaviors and generating SAE J3287 defined misbehavior reports.


## Directory Layout

```
libs/                 # Compiled asn1c shared libraries 
data/<PDU>/           # Sample encoded inputs
output/               # Generated conversions & reports
src/                  # Detection and generation logic
stubs/                # Helper files for ASN.1 deparameterization
```

## Prerequisites

Install Python dependencies:

```bash
pip install -r requirements.txt
```


## Building ASN.1 Shared Libraries

**ASN.1 definition modifications removing parameterization are required for compatibility with asn1c library.** 

1. Install open-source asn1c library from: https://github.com/mouse07410/asn1c.
2. Clone the ASN.1 Parameterized to Flat Translation Tool from: https://github.com/usdot-jpo-codehub/ASN.1-Parameterized-to-Flat-Translation-Tool.
3. Move the `stubs/` directory and the `build_asn_lib.sh` and `compile_asn1.sh` files into the base directory of the ASN.1 Parameterized to Flat Translation Tool.
4. Follow the instructions in the ASN.1 Parameterized to Flat Translation Tool README to generate deparameterized ASN.1 files:
```
python3 asn1_deparam.py --src [input_directory]
```
5. Add any missing imports (to be automated in future release of ASN.1 Parameterized to Flat Translation Tool). 
```
 EtsiTs103097Data -> EtsiTs103759Core.asn
 Ieee1609Dot2Data -> Ieee1609Dot2Dot1AcaRaInterface.asn and Ieee1609Dot2Dot1Acpc.asn
 V2xPduStream -> SaeJ3287AsrBsm.asn
```
6. Run the `compile_asn1.sh` script followed by the `build_asn_lib.sh` script:
```
./compile_asn1.sh
./build_asn_lib.sh
```
Note: If you run into an error with the `compile_asn1.sh` script, verify that the various directory paths in the script match your own directory structure and adjust if necessary. By default, the script contains the following: `../../asn1c/asn1c/asn1c -fcompound-names -S ../../asn1c/skeletons ../J3287_ASN_flat/*.asn`

7. Place the generated `libs/J3287.so` file into `Misbehavior-Detection/misbehavior-detection/libs/`.


## Misbehavior Detection Workflow

### File / Directory Mode

1. Generate shared library for SAE J3287 ASN.1 following instructions in above section.
2. Provide a COER-encoded IEEE1609Dot2Data file in `data/Ieee1609Dot2Data/`. This file should encompass a faulty (misbehaving) BSM. `Ieee1609Dot2Data_bad_accel.coer` has been provided for your convenience. This file contains a BSM with an acceleration exceeding the range allowed by the J3287 ASN.1 schema.
3. Run detection:
```
python3 src/detection.py --misbehaviors acceleration-ValueOutofRange --bsm data/Ieee1609Dot2Data/{filename}
```
4. Reports will be generated to `output/` directory.

Use `--debug` flag to emit JSON snapshots of the internal report structure.

### ODE Live-Stream Mode (Kafka)

The tool can subscribe directly to the ODE's `topic.OdeBsmJson` Kafka topic and run detection against BSMs as they arrive in real time.

1. Ensure the ODE stack is running and publishing BSMs to Kafka.
2. Start detection in Kafka mode:
```bash
python3 src/detection.py --kafka
```
The consumer connects to `localhost:9092` and subscribes to `topic.OdeBsmJson` by default. Override these with flags or environment variables (see [Environment Variables](#environment-variables) below).

4. Each incoming ODE message is decoded using the raw COER bytes stored in `metadata.asn1`. All configured misbehavior checks are run and any detections are written to `output/` exactly as in file mode.
5. Press **Ctrl-C** to stop the consumer gracefully.


## Command-Line Arguments

Primary usage:

```bash
python3 src/detection.py [options]
```

### Core Options

| Flag | Short Form | Required | Default | Description |
|---|---|---|---|---|
| `--misbehaviors` | `-m` | No | None | Space-separated list of one or more misbehavior checks to run. Will check all misbehaviors by default if no individual misbehaviors are provided. |
| `--bsm` | `-b` | No | `data/Ieee1609Dot2Data/Ieee1609Dot2Data_bad_accel.coer` | Path to a single BSM file or to a directory containing multiple files. Ignored when `--kafka` is set. |
| `--certs-dir` | `-c` | No | None | Path to an SCMS certificate bundle used to sign generated reports. Supports pseudonym bundles with a `download/` layout and RSU bundles with an `rsu-*/downloadFiles/` layout. |
| `--ma-key` | None | No | None | Path to the Misbehavior Authority recipient certificate. Use this together with `--certs-dir` when generating an sTE-wrapped report instead of a plaintext or signed-only report. |
| `--debug` | `-d` | No | Disabled | Prints the internal report representation as JSON for inspection while still writing encoded output files to `output/`. |

### Flag Usage Notes

- `--misbehaviors` accepts multiple values separated by spaces, for example: `--misbehaviors acceleration-ValueOutofRange security-HeaderPsidIncWithCertificate`. If the flag is unused, the tool will check against all available misbehaviors by default.
- `--bsm` can target either one file or an entire directory. When a directory is provided, every file in that directory is processed.
- If `--certs-dir` is omitted, reports will be generated as plaintext.
- If `--certs-dir` is included, but `--ma-key` is omitted, reports will be generated as signed but not encrypted.

### Supported Misbehaviors 

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

### Kafka Live-Stream Options

| Flag | Required | Default | Description |
|---|---|---|---|
| `--kafka` | No | Disabled | Subscribe to the ODE's Kafka topic and process BSMs from the live stream instead of reading from files. |
| `--kafka-bootstrap` | No | `$KAFKA_BOOTSTRAP` or `localhost:9092` | Kafka bootstrap server(s), e.g. `broker:9092`. |
| `--kafka-topic` | No | `$KAFKA_TOPIC` or `topic.OdeBsmJson` | Kafka topic to consume. |
| `--kafka-group-id` | No | `$KAFKA_GROUP_ID` or `misbehavior-detection` | Kafka consumer group ID. |

### Environment Variables

The Kafka connection settings can also be supplied via environment variables. CLI flags take precedence over environment variables.

| Variable | Description | Default |
|---|---|---|
| `KAFKA_BOOTSTRAP` | Kafka bootstrap server(s) | `localhost:9092` |
| `KAFKA_TOPIC` | Kafka topic to consume | `topic.OdeBsmJson` |
| `KAFKA_GROUP_ID` | Kafka consumer group ID | `misbehavior-detection` |

### Example Commands

Run an acceleration check against one input file:

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

Subscribe to the ODE Kafka stream using defaults:

```bash
python3 src/detection.py --kafka
```

Subscribe to a remote Kafka broker with specific misbehavior checks and signed reports:

```bash
python3 src/detection.py \
	--kafka \
	--kafka-bootstrap broker.example.com:9092 \
	--kafka-topic topic.OdeBsmJson \
	--misbehaviors acceleration-ValueOutofRange security-HeaderPsidIncWithCertificate \
	--certs-dir path/to/scms-bundle
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

**Example (OmniTrust pre-production RA):**

```bash
curl "https://ra.preprod.v2x.isscms.com/v3/ma-certificate?psid=20" \
    -o certs/ma_keys/iss_ma_public_key.cert
```

The response body is the raw COER-encoded `Certificate`.


## Certificate Caching

This tool supports caching of full certificates from input Basic Safety Message Data. Messages with full certificates will have the certificate data cached to the HashedId8 value of the data and any messages with only a digest will compare against the cache for matching certificates. 

If a matching certificate is found, the digest shall be replaced by the contents of the full certificate before being attached to a misbehavior report as evidence.

The cache does not persist between executions.
