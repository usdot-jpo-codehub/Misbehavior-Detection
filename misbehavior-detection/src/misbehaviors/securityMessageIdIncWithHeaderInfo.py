from typing import List, Dict
from misbehaviors.bsm_utils import BSM_VALID_ID
from misbehaviors.reportGenerator import ReportGenerator

class SecurityMessageIfIncWithHeaderInfo(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "security" 
    
    # securityHeaderIncWithSecurityProfile specifics functions
    ############################################################
    def securityMessageIfIncWithHeaderInfo(self, bsm : Dict):
        bsm_data = bsm['value'][1]['coreData']
        msg_id = bsm_data['messageId']

        if msg_id != 20:
            evidence = msg_id
            self.reports.append(evidence)
         
    ############################################################

    def generateMbr():
        return 

    # run_all_checks( List[JSON] ) => None
    # DESC: for every message, check for misbehavior
    def run_all_checks(self, bsm_jsons : List):
        for bsm in bsm_jsons:
            try: self.securityMessageIfIncWithHeaderInfo(bsm)
            except Exception as e: print(e) 
    
    
