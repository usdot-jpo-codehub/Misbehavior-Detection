import pandas 
from datetime import datetime
from typing import List, Dict
from misbehaviors.reportGenerator import ReportGenerator


class SecurityHeaderTimeOutsideCertificate(ReportGenerator):
    def __init__(self):
        self.reports = []
        self.target_class = "security"
    
    # securityHeaderIncWithSecurityProfile specifics functions
    ############################################################
    def securityHeaderTimeOutsideCertificate(self, certificate):
        signed_data = certificate["signedData"]
        signed_time = datetime.fromtimestamp(signed_data["headerInfo"]["generationTime"])
        
        cert_start_t = datetime.fromtimestamp(certificate["certificate"]['validityPeriod']['start'])
        cert_duration =  datetime.hour(certificate["certificate"]['validityPeriod']['duration'])
        cert_end_t = cert_start_t + cert_duration

        if signed_time < cert_start_t or signed_time > cert_end_t:
            evidence = {"header" : signed_time, "certificate" : certificate["certificate"]['validityPeriod']}
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
    
    
