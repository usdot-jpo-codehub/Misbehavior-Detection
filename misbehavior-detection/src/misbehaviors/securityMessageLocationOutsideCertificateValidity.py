from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 6

# Bounding boxes for UnCountryId values (1/10th-microdegree units, per IEEE 1609.2).
# 1 degree = 10,000,000 units.  USA (840) covers the contiguous 48 states.
COUNTRY_BOUNDS = {
    840: {
        "min_lat":  245_000_000,   # 24.5 N
        "max_lat":  495_000_000,   # 49.5 N
        "min_lon": -1_250_000_000, # 125.0 W
        "max_lon":   -660_000_000, # 66.0 W
    },
}

class SecurityMessageLocationOutsideCertificateValidity(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = []

    '''
    The message location (BSM coreData lat/lon) is outside the region in the certificate.
    Assumes toBeSigned.region contains identifiedRegion, a SequenceOfIdentifiedRegion whose
    first entry is countryOnly with UnCountryId 840 (United States).
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        core_data = bsm.get("value", {}).get("BasicSafetyMessage", {}).get("coreData", {})
        print('CORE DATA: ', core_data)
        msg_lat = core_data.get("latitude", core_data.get("lat"))
        msg_lon = core_data.get("longitude", core_data.get("long"))

        signer = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("signer", {})
        )
        certificates = signer.get("certificate", [])
        country_id = None
        if isinstance(certificates, list) and certificates:
            tbs_cert = certificates[0].get("toBeSigned", {})
            region = tbs_cert.get("region", {})
            identified_regions = region.get("identifiedRegion", [])
            if identified_regions:
                country_id = identified_regions[0].get("countryOnly")

        bounds = COUNTRY_BOUNDS.get(country_id) if country_id is not None else None

        if msg_lat is None or msg_lon is None:
            print("No message latitude/longitude; cannot validate against certificate")
        elif bounds is None:
            print(f"No known geographic bounds for country {country_id}; cannot validate")
        else:
            outside = (
                msg_lat < bounds["min_lat"] or msg_lat > bounds["max_lat"] or
                msg_lon < bounds["min_lon"] or msg_lon > bounds["max_lon"]
            )
            if outside:
                print(f"DETECTION: Message location outside certificate region: {msg_lat}, {msg_lon}")
                self.detections.append((self.tgt_id, self.obs_id, ieee_data))
            else:
                print("No inconsistency: message location within certificate region")

        return self.detections