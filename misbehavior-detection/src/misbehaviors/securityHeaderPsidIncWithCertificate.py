from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 3

class SecurityHeaderPsidIncWithCertificate(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 

    '''
    The psid in the security headerInfo is not contained in the appPermissions
    of the certificate, e.g., psid in the security headerInfo is equal to 32, but the appPermissions in the certificate does
    not include the value 32.
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        # Extract PSID from IEEE 1609.2 headerInfo
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )
        psid = header_info.get("psid")

        # Extract appPermissions PSIDs from signer certificate, if present
        signer = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("signer", {})
        )

        if not signer:
            print("No signer information found in IEEE 1609.2 data")
            return self.detections

        permitted_psids = []
        try:
            certificates = signer.get("certificate", [])
            if isinstance(certificates, list) and certificates:
                cert0 = certificates[0]
                tbs = cert0.get("toBeSigned", {})
                app_permissions = tbs.get("appPermissions", [])
                # Normalize permissions to a flat list of PSIDs
                for perm in app_permissions:
                    if isinstance(perm, dict):
                        if "psid" in perm:
                            permitted_psids.append(perm["psid"]) 
                        elif "subjectPermissions" in perm and isinstance(perm["subjectPermissions"], dict):
                            sp = perm["subjectPermissions"]
                            if "psid" in sp:
                                permitted_psids.append(sp["psid"]) 
        except Exception:
            # If structure doesn't match expectations, leave permitted_psids empty
            pass

        if psid is None:
            print("No PSID found in security headerInfo; cannot validate against certificate")
        elif psid not in permitted_psids:
            print(f"DETECTION: PSID {psid} in headerInfo not permitted by certificate")
            self.detections.append((self.tgt_id, self.obs_id, ieee_data))
        else:
            print(f"No inconsistency: PSID {psid} permitted by certificate")

        return self.detections