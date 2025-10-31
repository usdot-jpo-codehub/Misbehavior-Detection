# Misbehavior Detection and Reporting Tool

Open-source Python tool built using asn1c and ctypes for analyzing Basic Safety Messages (BSM) for misbehaviors and generating misbehavior reports.


## Directory Layout

```
libs/                 # Compiled asn1c shared libraries 
data/<PDU>/           # Sample encoded inputs (PER, OER, XER, JER)
output/               # Generated conversions & reports
src/                  # Detection and generation logic
```

## Building ASN.1 Shared Libraries

All required libraries to run this tool are included in this repository. However, if you would like to build your own libraries, you may do so with the following instructions. 

Note: ASN.1 definition modifications removing parameterization may be required for compatibility with asn1c library.

1. Install open-source asn1c library from: http://github.com/vlm/asn1c.
2. Generate C files from ASN.1 using asn1c (adjust skeleton path):
```
asn1c -fcompound-names -S ../asn1c/skeletons ../YOUR_ASN_DIR/*.asn
```
3. Compile to shared object:
```
gcc -I ../asn1c/skeletons/ -DPDU={PDU_NAME} -fPIC -shared -o {PDU_NAME}.so -lm *.c
```
4. Place `.so` in `libs/`.


## Misbehavior Detection Workflow

1. If not already present, generate shared library for SaeJ3287Data PDU from SAE J3287 ASN.1 following instructions in above section.
2. Provide a COER-encoded IEEE1609Dot2Data file in `data/Ieee1609Dot2Data/`.
3. Run detection:
```
python3 src/detection.py --pdu {pduname} --lib {libname} --misbehaviors acceleration-ValueOutofRange --bsm data/Ieee1609Dot2Data/{filename}
```
4. Reports will be generated to `output/` directory

Use `--debug` to emit JSON snapshots of the internal report structure.

## Supported Misbehaviors 

This tool currently supports detection and reporting of the `LongAcc-ValueTooLarge` misbehavior type with additional planned support for all other SAE J3287-specified misbehavior types. See [src/misbehaviors/README.md](src/misbehaviors/README.md) for more information.