import datetime
import xmltodict
import json
import ctypes
import encoder_utils, decoder_utils
from asn1c_bridge import load_lib, get_td

class ReportGenerator:
    def __init__(self):
        self.report = {}

    def print_report(self):
        print(self.report)

    def debug_report(self):
        now = datetime.datetime.now()
        # Format for filename: YYYYMMDD_HHMMSS
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        open(f"output/mbr-{timestamp}.json", "w").write(json.dumps(self.report, indent=4))
        print(f"Wrote mbr-{timestamp}.json")

    def encode_report(self):
        lib = ctypes.CDLL(f"libs/asn1clib.so")
        td = get_td(lib, "SaeJ3287Data")

        #self.report = self.report.pop('SaeJ3287Data', None)

        # data = json.dumps(self.report).encode('utf-8')
        # print(data[:212])
        # sptr, rval = decoder_utils.decode_jer(lib, td, data)
        # print(f"JER decode: code={rval.code} consumed={rval.consumed}")
        # if rval.code != 0:
        #     raise SystemExit(f"JER decode failed")

        data = xmltodict.unparse(self.report, full_document=False).encode('utf-8')
        sptr, rval = decoder_utils.decode_xer(lib, td, data)
        print(f"XER decode: code={rval.code} consumed={rval.consumed}")
        if rval.code != 0:
            raise SystemExit(f"XER decode failed")

        mbr = encoder_utils.encode_oer(lib, td, sptr)
        return mbr

    def generate_report(self, target_id, observation_id, evidence):
        # generationTime = number of (TAI) microseconds since 00:00:00 UTC, 1 January, 2004
        start_date = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
        current_date = datetime.datetime.now(tz=datetime.timezone.utc)
        time_difference = current_date - start_date
        leap_seconds = 5
        total_tai_seconds = time_difference.total_seconds() + leap_seconds
        tai_microseconds = int(total_tai_seconds * 1_000_000)

        self.report = {
            "SaeJ3287Data": {
                "version": 1,
                "content": {
                    "plaintext": {
                        "generationTime": tai_microseconds,
                        "observationLocation": {
                            "latitude": 10,
                            "longitude": 10,
                            "elevation": 10,
                        },
                        "report": {
                            "aid": 32,
                            "content": {
                                "AsrBsm": {
                                    "observations": {
                                        "ObservationsByTarget-SetMbObsTgtsBsm": [
                                            {
                                                "tgtId": target_id,
                                                "observations": {
                                                    "longAcc": [
                                                        {
                                                            "obsId": observation_id,
                                                            "obs": {
                                                                "LongAcc-ValueTooLarge": {}
                                                            },
                                                        }
                                                    ]
                                                },
                                            }
                                        ]
                                    },
                                    "v2xPduEvidence": {
                                        "V2xPduStream": {
                                            "type": 2,
                                            "v2xPdus": {
                                                "ieee1609Dot2": [
                                                    {
                                                        "protocolVersion": 3,
                                                        "content": {
                                                            "unsecuredData": evidence
                                                        },
                                                    }
                                                ]
                                            },
                                            "subjectPduIndex": 0,
                                        }
                                    },
                                    "nonV2xPduEvidence": {},
                                }
                            },
                        },
                    }
                },
            }
        }

        mbr = self.encode_report()

        return mbr