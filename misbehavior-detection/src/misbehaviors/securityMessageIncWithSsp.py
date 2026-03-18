from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 4

class SecurityMessageIncWithSsp(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 
    
    '''
    The message payload is inconsistent with the SSP in the certificate, as specified in 
    SAE J3161/1 Appendix C, e.g., partII.supplementalVehicleExt.classDetails.role.police 
    is present in the BasicSafetyMessage but the relevant SSP in the certificate 
    does not permit DE_BasicVehicleRole to be set to police.
    '''
    # SAE J3161/1 Appendix C SSP bit layout for PSID 32 (BSM):
    # Byte 0: SSP version (0x01)
    # Byte 1: Role permission bits (MSB = bit 7)
    #   bit 7 (0x80): police
    #   bit 6 (0x40): fire
    #   bit 5 (0x20): ambulance
    #   bit 4 (0x10): dot
    #   bit 3 (0x08): transit
    #   bit 2 (0x04): emergency
    #   bit 1 (0x02): roadRescue
    #   bit 0 (0x01): roadWork
    ROLE_SSP_BITS = {
        "police":     (1, 0x80),
        "fire":       (1, 0x40),
        "ambulance":  (1, 0x20),
        "dot":        (1, 0x10),
        "transit":    (1, 0x08),
        "emergency":  (1, 0x04),
        "roadRescue": (1, 0x02),
        "roadWork":   (1, 0x01),
    }

    def analyze_bsm(self, ieee, bsm, ieee_data):
        # Extract PSID from headerInfo to match against certificate appPermissions
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )
        psid = header_info.get("psid")

        # Extract SSP bytes from certificate's appPermissions for the matching PSID.
        # The certificate is only present when signer is "certificate" (not "digest").
        signer = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("signer", {})
        )

        cert_ssp_bytes = None
        try:
            certificates = signer.get("certificate", [])
            if isinstance(certificates, list) and certificates:
                cert0 = certificates[0]
                app_permissions = cert0.get("toBeSigned", {}).get("appPermissions", [])
                for perm in app_permissions:
                    if isinstance(perm, dict) and perm.get("psid") == psid:
                        ssp = perm.get("ssp")
                        if ssp:
                            if "opaque" in ssp:
                                cert_ssp_bytes = bytes.fromhex(ssp["opaque"])
                            elif "bitmapSsp" in ssp:
                                cert_ssp_bytes = bytes.fromhex(ssp["bitmapSsp"]["sspValue"])
                        break
        except Exception:
            pass

        # Extract claimed vehicle role from partII supplementalVehicleExt (partII-Id=2)
        bsm_content = bsm.get("value", {}).get("BasicSafetyMessage", {})
        claimed_role = None
        for part in bsm_content.get("partII", []):
            if isinstance(part, dict) and part.get("partII-Id") == 2:
                sup_ext = part.get("partII-Value", {}).get("SupplementalVehicleExtensions", {})
                class_details = sup_ext.get("classDetails", {})
                if isinstance(class_details, dict):
                    claimed_role = class_details.get("role")
                break

        if claimed_role is None or claimed_role == "basicVehicle":
            print("No restricted role claimed in BSM supplementalVehicleExt; no SSP check needed")
            return self.detections

        if claimed_role not in self.ROLE_SSP_BITS:
            print(f"Role '{claimed_role}' has no defined SSP restriction; no check needed")
            return self.detections

        if cert_ssp_bytes is None:
            print(f"No SSP for PSID {psid} in certificate; cannot validate claimed role '{claimed_role}'")
            return self.detections

        byte_idx, bit_mask = self.ROLE_SSP_BITS[claimed_role]
        role_permitted = (len(cert_ssp_bytes) > byte_idx) and bool(cert_ssp_bytes[byte_idx] & bit_mask)

        if not role_permitted:
            print(f"DETECTION: BSM claims role '{claimed_role}' but certificate SSP does not permit it")
            self.detections.append((self.tgt_id, self.obs_id, ieee_data))
        else:
            print(f"No inconsistency: certificate SSP permits role '{claimed_role}'")

        return self.detections