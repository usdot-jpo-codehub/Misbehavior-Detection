import pandas 
from typing import List, Dict

from misbehaviors.reportGenerator import ReportGenerator

class SecurityHeaderLocationOutsideCertificateValidity(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "security"
    
    ############################################################ 
    def securityHeaderLocationOutsideCertificateValidity(self, certificate):
        '''
        perturb_security_header_location_outside_certificate_validity

        The coreData.lat and/or coreData.long of BasicSafetyMessage is outside the region in the certificate
        '''
        signed_data = certificate["signedData"]
        header_loc = signed_data["headerInfo"]["generationLocation"]

        cert_locs = certificate["certificate"]["identifiedRegion"]
        if header_loc not in cert_locs: 
            evidence = {"header" : header_loc, "certificate" : cert_locs}
            self.reports.append(evidence)

    ############################################################

    def generateMbr(self):
        report = None
        # TODO: add encoding of reports
        return report


    # run_all_checks( List[JSON] ) => None
    # DESC: for every message, check for misbehavior
    def run_all_checks(self, bsm_jsons : List):
        for bsm in bsm_jsons:
            try: self.securityHeaderIncWithSecurityProfile(bsm)
            except Exception as e: print(e) 
    
    