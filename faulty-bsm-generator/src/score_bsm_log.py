#!/usr/bin/env python3
"""
WYDOT BSM Log File Diagnostic Tool
===================================
Run this FIRST to understand your file's actual byte layout before parsing.

Usage: python3 diagnose_bsm_log.py <your_log_file.bin>

It will:
1. Hex-dump the first 128 bytes so you can see the raw data
2. Try multiple known header sizes (from different OBU firmware versions)
3. Print what each interpretation looks like so you can spot the sane one
"""

import struct
import sys

LOG_RECORD_TYPES = {
    0: 'DN_MSG',
    1: 'ENVIRONMENT_MSG',
    2: 'DRIVER_ALERT',
    3: 'UPGRADES',
    4: 'SYSTEM_LOG',
    5: 'RX_MSG',
    6: 'SCMS',
    7: 'BSM_TX',
    8: 'BSM_RX',
}

def hexdump(data, max_bytes=256):
    print(f"\n{'='*60}")
    print(f"HEX DUMP (first {min(len(data), max_bytes)} of {len(data)} bytes)")
    print(f"{'='*60}")
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}: {hex_part:<47}  {asc_part}")

def try_header(data, offset, fmt, fmt_name, fields, endian_label):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        print(f"  [Not enough bytes for {fmt_name}]")
        return None
    try:
        values = struct.unpack(fmt, data[offset:offset+size])
        result = dict(zip(fields, values))
        return result, size
    except struct.error as e:
        print(f"  [Unpack error for {fmt_name}: {e}]")
        return None

def assess(result, header_size, total_file_size):
    """Score how plausible this parse is."""
    issues = []
    score = 0

    rt = result.get('record_type', 99)
    if rt in LOG_RECORD_TYPES:
        score += 10
    else:
        issues.append(f"unknown record_type={rt}")

    direction = result.get('direction', 99)
    if direction in (0, 1):
        score += 5
    else:
        issues.append(f"direction={direction} (expected 0 or 1)")

    lat = result.get('lat', 0)
    if -90_000_0000 <= lat <= 90_000_0000:
        score += 5
    else:
        issues.append(f"lat out of range: {lat}")

    lon = result.get('lon', 0)
    if -180_000_0000 <= lon <= 180_000_0000:
        score += 5
    else:
        issues.append(f"lon out of range: {lon}")

    plen = result.get('payload_length', 0)
    if 0 < plen < 2000:
        score += 10
    elif plen == 0:
        issues.append("payload_length=0")
    else:
        issues.append(f"payload_length={plen} (suspiciously large)")

    # Check if a next record would make sense
    next_offset = header_size + plen
    if next_offset < total_file_size:
        next_rt = data_global[next_offset] if next_offset < total_file_size else None
        if next_rt is not None and next_rt in LOG_RECORD_TYPES:
            score += 20  # Strong signal!
        elif next_rt is not None:
            issues.append(f"next byte after record = 0x{next_rt:02x} (not a valid record type)")

    utc = result.get('utc_sec', 0)
    # Valid range: 2010-01-01 to 2030-01-01 in epoch seconds
    if 1_262_304_000 <= utc <= 1_893_456_000:
        score += 5
    else:
        issues.append(f"utc_sec={utc} (not in 2010-2030 range)")

    return score, issues

data_global = b''

def main():
    global data_global

    with open("data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin", 'rb') as f:
        data = f.read()
    data_global = data

    print(f"\nFile: data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin")
    print(f"Size: {len(data)} bytes")

    hexdump(data, max_bytes=128)

    print(f"\n{'='*60}")
    print("HEADER FORMAT CANDIDATES")
    print(f"{'='*60}")
    print("(Probing offset 0 with different known struct layouts)\n")

    # -----------------------------------------------------------------
    # Known variants of the WYDOT log record header.
    # The OBU firmware has changed over the years; field order differs.
    # All multi-byte fields are little-endian in the C struct (packed).
    # -----------------------------------------------------------------
    candidates = [
        # (format_string, name, [field_names])
        # Variant A - most commonly documented (little-endian, no padding)
        # record_type(1) + direction(1) + utc(4) + msec(2) + lat(4) + lon(4) + elev(4) + speed(2) + heading(2) + payload_len(2) = 26
        ('<BBIHiiiHHH', 'Variant-A LE (26 bytes)',
         ['record_type','direction','utc_sec','msec','lat','lon','elev','speed','heading','payload_length']),

        # Variant B - with verifyStatus byte after msec
        # record_type(1) + direction(1) + utc(4) + msec(2) + verify(1) + lat(4) + lon(4) + elev(4) + speed(2) + heading(2) + payload_len(2) = 27
        ('<BBIHBiiiHHH', 'Variant-B LE (27 bytes, +verifyStatus)',
         ['record_type','direction','utc_sec','msec','verify_status','lat','lon','elev','speed','heading','payload_length']),

        # Variant C - big-endian versions of the above
        ('>BBIHiiiHHH', 'Variant-C BE (26 bytes)',
         ['record_type','direction','utc_sec','msec','lat','lon','elev','speed','heading','payload_length']),

        ('>BBIHBiiiHHH', 'Variant-D BE (27 bytes, +verifyStatus)',
         ['record_type','direction','utc_sec','msec','verify_status','lat','lon','elev','speed','heading','payload_length']),

        # Variant E - direction after record_type but elev is uint16 not int32
        ('<BBIHiIHHH', 'Variant-E LE (24 bytes, elev=uint32)',
         ['record_type','direction','utc_sec','msec','lat','lon','elev','speed','heading','payload_length']),

        # Variant F - no elevation field (older firmware)
        # record_type(1) + direction(1) + utc(4) + msec(2) + lat(4) + lon(4) + speed(2) + heading(2) + payload_len(2) = 22
        ('<BBIHiiHHH', 'Variant-F LE (22 bytes, no elev)',
         ['record_type','direction','utc_sec','msec','lat','lon','speed','heading','payload_length']),

        # Variant G - record_type only, then payload length immediately (very minimal)
        ('<BH', 'Variant-G LE (3 bytes, just type+len)',
         ['record_type','payload_length']),

        # Variant H - some versions use uint16 msec before utc
        ('<BHIiiiHHH', 'Variant-H LE (26 bytes, msec before utc)',
         ['record_type','msec','utc_sec','lat','lon','elev','speed','heading','payload_length']),
    ]

    results = []
    for fmt, name, fields in candidates:
        size = struct.calcsize(fmt)
        parsed = try_header(data, 0, fmt, name, fields, '')
        if parsed is None:
            continue
        result, hdr_size = parsed
        score, issues = assess(result, hdr_size, len(data))

        lat_f = result.get('lat', 0) / 1e7
        lon_f = result.get('lon', 0) / 1e7
        utc = result.get('utc_sec', 0)
        plen = result.get('payload_length', 0)
        rt = result.get('record_type', 0)
        rt_name = LOG_RECORD_TYPES.get(rt, f'UNKNOWN({rt})')

        print(f"[Score={score:3d}] {name}")
        print(f"         type={rt_name}, dir={result.get('direction','?')}, utc={utc}, "
              f"lat={lat_f:.4f}, lon={lon_f:.4f}, payload_len={plen}")
        if issues:
            print(f"         Issues: {', '.join(issues)}")
        print()
        results.append((score, name, fmt, fields, size))

    results.sort(reverse=True)
    best_score, best_name, best_fmt, best_fields, best_size = results[0]

    print(f"\n{'='*60}")
    print(f"BEST CANDIDATE: {best_name} (score={best_score})")
    print(f"{'='*60}")

    if best_score < 30:
        print("\n⚠️  WARNING: No candidate scored well (best={best_score}/55).")
        print("   This may mean:")
        print("   1. The file has a non-standard header (custom OBU firmware)")
        print("   2. There is a file-level prefix/magic before the first record")
        print("   3. The file is not a WYDOT binary log at all\n")
        print("   Try running with --scan to search for valid record boundaries.")
    else:
        print(f"\nSuggested struct format string: '{best_fmt}'")
        print(f"Header size: {best_size} bytes")
        print(f"Fields: {best_fields}")
        print(f"\nNext step: use split_bsm_log.py with HEADER_FORMAT = '{best_fmt}'")
        print(f"           and HEADER_FIELDS = {best_fields}")

    # Also do a brute-force scan for plausible record starts
    print(f"\n{'='*60}")
    print("BRUTE-FORCE SCAN for valid record_type bytes (0-8)")
    print(f"{'='*60}")
    found = []
    for i in range(min(len(data), 512)):
        if data[i] in range(9):  # 0-8 are valid record types
            found.append((i, data[i], LOG_RECORD_TYPES.get(data[i], '?')))

    print(f"First 20 offsets where byte value is 0-8:")
    for off, val, name in found[:20]:
        print(f"  offset {off:4d} (0x{off:04x}): 0x{val:02x} = {name}")

    if found:
        print(f"\nIf records start at offset {found[0][0]}, there may be a file header before records.")

if __name__ == '__main__':
    main()