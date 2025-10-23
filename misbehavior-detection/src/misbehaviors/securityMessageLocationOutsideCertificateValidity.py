import pandas 
from typing import List, Dict
from misbehaviors.reportGenerator import ReportGenerator

class SecurityMessageLocationOutsideCertificateValidity(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "security" 
    
    # securityHeaderIncWithSecurityProfile specifics functions
    ############################################################
    def securityMessageLocationOutsideCertificateValidity(bsm, certificate):
        bsm_data = bsm['value'][1]['coreData']
        old_lat, old_lon = bsm_data['lat'], bsm_data['lon']
        return 
    

    ############################################################

    def generateMbr():
        return 

    # run_all_checks( List[JSON] ) => None
    # DESC: for every message, check for misbehavior
    def run_all_checks(self, bsm_jsons : List):
        for bsm in bsm_jsons:
            try: self.securityMessageLocationOutsideCertificateValidity(bsm)
            except Exception as e: print(e) 
    
