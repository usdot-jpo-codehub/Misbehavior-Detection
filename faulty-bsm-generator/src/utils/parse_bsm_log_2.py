#!/usr/bin/env python3
"""
WYDOT BSM Log File Splitter
============================
Splits a bsmLogDuringEvent / bsmTx / rxMsg / dnMsg binary log file into
individual single-record .bin files suitable for upload to the JPO-ODE.

IMPORTANT — what each output file must contain:
  The ODE's BsmLogFileParser parses the 26-byte log header itself before
  forwarding the payload to the ASN.1 codec. Each output file must therefore
  contain the COMPLETE original record bytes:
      [26-byte header] + [payload bytes]
  NOT the payload alone.

CONFIRMED 26-byte header layout (all little-endian, packed):
  [0]     direction      uint8   0=EV_TX 1=RV_TX 2=EV_RX 3=RV_RX
  [1:5]   latitude       int32   degrees x 1e7
  [5:9]   longitude      int32   degrees x 1e7
  [9:11]  elevation      int16   0.1 m units
  [11:13] speed          uint16  0.02 m/s units
  [13:15] heading        uint16  0.0125 degree units
  [15]    unk1           uint8   (security/WAVE metadata)
  [16]    unk2           uint8   (security/WAVE metadata)
  [17:21] utcTimeInSec   uint32  Unix epoch seconds
  [21:23] mSec           uint16  milliseconds
  [23]    logRecordType  uint8   0-8
  [24:26] payloadLength  uint16  byte length of following payload
  [26+]   payload               IEEE 1609.2 COER-wrapped ASN.1 UPER message

ODE filename prefix routing (LogFileParserFactory):
  bsmLogDuringEvent  ->  BsmLogFileParser
  bsmTx              ->  BsmLogFileParser
  rxMsg              ->  RxMsgFileParser
  dnMsg              ->  DnMsgFileParser

Usage:
    python3 split_bsm_log.py <logfile.bin> [output_dir]
"""

import struct
import sys
import os
import datetime

LOG_RECORD_TYPES = {
    0: 'DN_MSG', 1: 'ENVIRONMENT_MSG', 2: 'DRIVER_ALERT',
    3: 'UPGRADES', 4: 'SYSTEM_LOG', 5: 'RX_MSG', 6: 'SCMS',
    7: 'BSM_TX', 8: 'BSM_RX',
}
DIRECTION_NAMES = {0: 'EV_TX', 1: 'RV_TX', 2: 'EV_RX', 3: 'RV_RX'}

HEADER_FORMAT = '<BiihHHBBIHBH'
HEADER_FIELDS = [
    'direction', 'lat', 'lon', 'elev',
    'speed', 'heading', 'unk1', 'unk2',
    'utc_sec', 'msec', 'log_record_type', 'payload_length',
]
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 26 bytes
assert HEADER_SIZE == 26


def infer_ode_prefix(filepath):
    base = os.path.basename(filepath)
    for prefix in ('bsmLogDuringEvent', 'bsmTx', 'rxMsg', 'dnMsg'):
        if base.startswith(prefix):
            return prefix
    print(f"WARNING: '{base}' doesn't start with a known ODE prefix.")
    print("         Defaulting to 'bsmLogDuringEvent'.")
    return 'bsmLogDuringEvent'


def parse_record(data, offset):
    if offset + HEADER_SIZE > len(data):
        return None, offset
    try:
        values = struct.unpack_from(HEADER_FORMAT, data, offset)
    except struct.error:
        return None, offset

    rec = dict(zip(HEADER_FIELDS, values))
    plen = rec['payload_length']
    if plen > 10000:
        return None, offset
    record_end = offset + HEADER_SIZE + plen
    if record_end > len(data):
        return None, offset

    # Store the COMPLETE raw record bytes (header + payload) — this is what
    # each output file must contain so the ODE can parse the header itself.
    rec['_raw_record'] = data[offset:record_end]
    rec['_payload']    = data[offset + HEADER_SIZE:record_end]
    rec['_offset']     = offset
    rec['_next']       = record_end
    rec['_lat_deg']    = rec['lat'] / 1e7
    rec['_lon_deg']    = rec['lon'] / 1e7
    rec['_elev_m']     = rec['elev'] / 10.0
    rec['_dir_name']   = DIRECTION_NAMES.get(rec['direction'], f"UNK{rec['direction']}")
    rec['_type_name']  = LOG_RECORD_TYPES.get(rec['log_record_type'],
                                               f"UNKNOWN{rec['log_record_type']}")
    try:
        rec['_dt'] = datetime.datetime.fromtimestamp(rec['utc_sec'], datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        rec['_dt'] = None
    return rec, record_end


def is_sane(rec):
    if not (-90 <= rec['_lat_deg'] <= 90):
        return False
    if not (-180 <= rec['_lon_deg'] <= 180):
        return False
    if rec['direction'] not in (0, 1, 2, 3):
        return False
    if rec['_dt'] is None or not (2010 <= rec['_dt'].year <= 2035):
        return False
    return True


def parse_file(filepath, verbose=True):
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File  : {filepath}")
    print(f"Size  : {len(data)} bytes")
    print(f"Header: {HEADER_SIZE} bytes  ({HEADER_FORMAT})")
    print()

    records, offset, bad_run = [], 0, 0
    while offset < len(data):
        rec, next_offset = parse_record(data, offset)
        if rec is None or not is_sane(rec):
            offset += 1
            bad_run += 1
            if bad_run > 100:
                print(f"ERROR: 100+ consecutive bad records near offset {offset}. Wrong format?")
                break
            continue

        bad_run = 0
        rec['_num'] = len(records)
        if verbose:
            dt = rec['_dt'].strftime('%Y-%m-%d %H:%M:%S') if rec['_dt'] else '???'
            print(f"  [{rec['_num']:4d}] off={offset:6d}  {rec['_type_name']:12s}"
                  f"  {rec['_dir_name']:5s}  {dt}.{rec['msec']:03d}"
                  f"  lat={rec['_lat_deg']:10.6f}  lon={rec['_lon_deg']:11.6f}"
                  f"  elev={rec['_elev_m']:7.1f}m"
                  f"  plen={rec['payload_length']:4d}"
                  f"  total={len(rec['_raw_record'])}b")
        records.append(rec)
        offset = next_offset

    return records


def extract(filepath, output_dir=None, verbose=True):
    if output_dir is None:
        base = os.path.splitext(os.path.basename(filepath))[0]
        output_dir = base + '_extracted'
    os.makedirs(output_dir, exist_ok=True)

    ode_prefix = infer_ode_prefix(filepath)
    records = parse_file(filepath, verbose=verbose)

    saved = 0
    for rec in records:
        dt_str = rec['_dt'].strftime('%Y%m%dT%H%M%S') if rec['_dt'] else 'unknown'
        fname = f"{ode_prefix}_{rec['utc_sec']}_{rec['msec']:03d}_{rec['_num']:04d}.bin"
        out_path = os.path.join(output_dir, fname)
        # Write the COMPLETE record (header + payload), not payload alone.
        with open(out_path, 'wb') as f:
            f.write(rec['_raw_record'])
        saved += 1

    print(f"\nTotal records : {len(records)}")
    print(f"Files saved   : {saved}  ->  {output_dir}/")
    print(f"ODE prefix    : '{ode_prefix}'")
    print(f"\nEach file contains the full 26-byte header + payload,")
    print(f"as required by BsmLogFileParser.")
    return records


if __name__ == '__main__':
    extract("data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin", "out_msgs")