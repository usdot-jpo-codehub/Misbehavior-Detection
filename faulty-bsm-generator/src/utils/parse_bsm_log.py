FILE = "data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin"
from test_faultybsm import read_file

#!/usr/bin/env python3
import argparse
import gzip
import io
import os
import struct
from pathlib import Path
from typing import BinaryIO, Tuple


HEADER_LEN = 26  # bsmLogRecHeader/receivedMsgRecord layout is 26 bytes packed :contentReference[oaicite:3]{index=3}


def open_maybe_gzip(path: str) -> BinaryIO:
    f = open(path, "rb")
    magic = f.read(2)
    f.seek(0)
    if magic == b"\x1f\x8b" or path.endswith(".gz"):
        f.close()
        return gzip.open(path, "rb")
    return f


def read_sample(path: str, n: int = 1024 * 1024) -> bytes:
    with open_maybe_gzip(path) as f:
        return f.read(n)


def score_parse(sample: bytes, endian: str, start: int, max_records: int = 200) -> int:
    """Return how many consecutive records we can parse starting at offset start."""
    off = start
    ok = 0
    for _ in range(max_records):
        if off + HEADER_LEN > len(sample):
            break
        # Direction/rxFrom is a single byte; for BSM logs commonly 0/1. (Not strictly required.)
        direction = sample[off]
        length = struct.unpack_from(endian + "H", sample, off + 24)[0]
        if not (0 <= direction <= 5):  # permissive
            break
        if not (5 <= length <= 20000):  # permissive; typical messages are far smaller
            break
        nxt = off + HEADER_LEN + length
        if nxt > len(sample):
            break
        ok += 1
        off = nxt
    return ok


def infer_endian_and_start(sample: bytes) -> Tuple[str, int]:
    # Try a small window of possible starts in case the file has a prefix.
    best = ("<", 0, -1)  # endian, start, score
    for endian in ("<", ">"):
        for start in range(0, min(4096, max(0, len(sample) - HEADER_LEN))):
            s = score_parse(sample, endian, start)
            if s > best[2]:
                best = (endian, start, s)
            # early exit if it's clearly correct
            if s >= 50:
                return endian, start
    return best[0], best[1]


def split_log(in_path: str, out_dir: str, write_hex: bool) -> None:
    sample = read_sample(in_path)
    endian, start = infer_endian_and_start(sample)

    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)
    hex_file = (outp / "messages.hex").open("w") if write_hex else None

    # Stream parse (don’t load full log in RAM)
    with open_maybe_gzip(in_path) as f:
        # Skip prefix bytes if needed
        if start:
            _ = f.read(start)

        i = 0
        while True:
            hdr = f.read(HEADER_LEN)
            if len(hdr) == 0:
                break
            if len(hdr) < HEADER_LEN:
                raise ValueError(f"Truncated header at record {i} (got {len(hdr)} bytes)")

            length = struct.unpack_from(endian + "H", hdr, 24)[0]
            payload = f.read(length)
            if len(payload) < length:
                raise ValueError(f"Truncated payload at record {i} (expected {length}, got {len(payload)})")

            # Write raw payload bytes
            (outp / f"msg_{i:06d}.bin").write_bytes(payload)

            # Optionally write hex line for replay tools
            if hex_file is not None:
                hex_file.write(payload.hex() + "\n")

            i += 1

    if hex_file is not None:
        hex_file.close()

    print(f"Done. Parsed {i} records.")
    print(f"Endian={ 'little' if endian=='<' else 'big' }, start_offset={start}")
    print(f"Outputs in: {outp.resolve()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin", help="Input WYDOT OBU log (e.g., bsmLogDuringEvent.gz)")
    ap.add_argument("--out_dir", default="out_msgs", help="Directory to write msg_*.bin (and messages.hex if enabled)")
    ap.add_argument("--write-hex", action="store_true", help="Also write messages.hex (one payload hex per line)")
    args = ap.parse_args()
    split_log(args.input, args.out_dir, args.write_hex)


if __name__ == "__main__":
    main()

