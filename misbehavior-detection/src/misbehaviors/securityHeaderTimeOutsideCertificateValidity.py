from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 5

class SecurityHeaderTimeOutsideCertificate(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 
    
    '''
    The generationTime in the security headerInfo is outside the validity 
    period of the certificate.
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )
        gen_time = header_info.get("generationTime")

        signer = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("signer", {})
        )
        certificates = signer.get("certificate", [])
        start = None
        end = None
        if isinstance(certificates, list) and certificates:
            tbs_cert = certificates[0].get("toBeSigned", {})
            validity = tbs_cert.get("validityPeriod", {})
            start = validity.get("start")
            duration = validity.get("duration").get("hours")
            if isinstance(start, int) and isinstance(duration, int):
                end = start + duration

        if not isinstance(gen_time, int):
            print("No generationTime in headerInfo; cannot validate against certificate")
        elif start is None or end is None:
            print("No certificate validityPeriod found; cannot validate")
        else:
            outside = gen_time < start or gen_time > end
            if outside:
                print(f"DETECTION: Header generationTime outside certificate validity: {gen_time} not in [{start}, {end}]")
                self.detections.append((self.tgt_id, self.obs_id, ieee_data))
            else:
                print("No inconsistency: header generationTime within certificate validity")

        return self.detections