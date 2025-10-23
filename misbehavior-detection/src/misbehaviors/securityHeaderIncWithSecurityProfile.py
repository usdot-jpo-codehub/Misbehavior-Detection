from typing import List, Dict

from misbehaviors.reportGenerator import ReportGenerator

class SecurityHeaderIncWithSecurityProfile(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "security"
    
    ############################################################
    def securityHeaderIncWithSecurityProfile(self, certificate : Dict):
        '''
        security_message_id_inc_with_security_profile

        The security headerInfo is inconsistent with the security profile specified in
        SAE J2945/1 section 6.1.2.2 as referred to from SAE J3161/1 section 6.1.2, e.g., generationTime is absent in the
        security headerInfo but is required to be present in the security profile.
        '''
        headerInfo = certificate['signedData']['headerInfo']

        profile_items = ['generationTime', 'psid']
        if any([item not in headerInfo for item in profile_items]):
            evidence = headerInfo
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
    
    
