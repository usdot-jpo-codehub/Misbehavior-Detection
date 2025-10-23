import pandas 
from misbehaviors.reportGenerator import ReportGenerator

class SecurityHeaderPsidIncWithCertificate(ReportGenerator):
    def __init__(self):
        self.reports = []
        self.target_class = "security"
    
    # securityHeaderIncWithSecurityProfile specifics functions
    ############################################################
    def SecurityHeaderPsidIncWithCertificate(self, certificate):
        '''
        perturb_security_header_psid_inc_with_certificate

        The psid in the security headerInfo is not contained in the appPermissions
        of the certificate, e.g., psid in the security headerInfo is equal to 32, but the appPermissions in the certificate does
        not include the value 32.
        '''
        signed_data = certificate["signedData"]
        header_data = signed_data["headerInfo"]

        signed_psid = header_data["psid"]
        cert_psid = certificate["certificate"]["appPermissions"]["psid"]
        if signed_psid != cert_psid:
            evidence = {"certificate" : cert_psid, "header" : signed_psid}
            self.reports.append(evidence)
    

    ############################################################

    def generateMbr():
        return 

     # run_all_checks( List[JSON] ) => None
    # DESC: for every message, check for misbehavior
    def run_all_checks(self, bsm_json : list):
        for bsm in bsm_json:
            try: self.SecurityHeaderPsidIncWithCertificate(bsm)
            except Exception as e: print(e)
    
    
    
    
