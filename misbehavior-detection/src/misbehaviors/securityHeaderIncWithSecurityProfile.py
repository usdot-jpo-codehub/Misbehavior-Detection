from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 2

class SecurityHeaderIncWithSecurityProfile(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 

    '''
    The security headerInfo is inconsistent with the security profile specified in
    SAE J2945/1 section 6.1.2.2 as referred to from SAE J3161/1 section 6.1.2, e.g., generationTime is absent in the
    security headerInfo but is required to be present in the security profile.
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        # Check IEEE 1609.2 headerInfo against the J2945/1 security profile:
        # - generationTime must be PRESENT
        # - generationLocation must be ABSENT
        # - expiryTime must be ABSENT
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )

        has_generation_time = "generationTime" in header_info
        has_generation_location = "generationLocation" in header_info
        has_expiry_time = "expiryTime" in header_info

        violation = False

        if not has_generation_time:
            print("DETECTION: Security headerInfo missing required generationTime")
            violation = True

        if has_generation_location:
            print("DETECTION: Security headerInfo contains forbidden generationLocation")
            violation = True

        if has_expiry_time:
            print("DETECTION: Security headerInfo contains forbidden expiryTime")
            violation = True

        if violation:
            self.detections.append((self.tgt_id, self.obs_id, ieee_data))
        else:
            print("No inconsistency: headerInfo conforms to security profile")

        return self.detections