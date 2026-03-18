from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 7

# Bounding boxes for UnCountryId values (1/10th-microdegree units, per IEEE 1609.2)
# 1 degree = 10,000,000 units
COUNTRY_BOUNDS = {
    840: {
        "min_lat":  245_000_000,   # 24.5 N
        "max_lat":  495_000_000,   # 49.5 N
        "min_lon": -1_250_000_000, # 125.0 W
        "max_lon":   -660_000_000, # 66.0 W
    },
}

class SecurityHeaderLocationOutsideCertificateValidity(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = []

    '''
    The generationLocation in the security headerInfo is outside the region in the certificate.
    Assumes toBeSigned.region contains identifiedRegion, a SequenceOfIdentifiedRegion whose
    first entry is countryOnly with UnCountryId 840 (United States).
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )

        gen_loc = header_info.get("generationLocation")
        def _lat_lon(d):
            if not isinstance(d, dict):
                return None, None
            lat = d.get("latitude", d.get("lat"))
            lon = d.get("longitude", d.get("long"))
            return lat, lon

        gen_lat, gen_lon = _lat_lon(gen_loc)

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

        if gen_lat is None or gen_lon is None:
            print("No generationLocation in headerInfo; cannot validate against certificate")
        elif bounds is None:
            print(f"No known geographic bounds for country {country_id}; cannot validate")
        else:
            outside = (
                gen_lat < bounds["min_lat"] or gen_lat > bounds["max_lat"] or
                gen_lon < bounds["min_lon"] or gen_lon > bounds["max_lon"]
            )
            if outside:
                print(f"DETECTION: Header generationLocation outside certificate region: {gen_lat}, {gen_lon}")
                self.detections.append((self.tgt_id, self.obs_id, ieee_data))
            else:
                print("No inconsistency: header generationLocation within certificate region")

        return self.detections