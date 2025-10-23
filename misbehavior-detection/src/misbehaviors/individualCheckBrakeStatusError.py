from typing import List, Dict

from misbehaviors.reportGenerator import ReportGenerator

class CheckBrakeStatusError(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "individual" 
    
    '''
    ############################################################
    # checkBrakeStatusError( bsm : Dict ) => None
    This algorithm flags BSMs with improper brake status format by checking 
    if digit length is greater than 5 or if there exists a digit that is not 1 or 0.    '''
    def checkBrakeStatusError(self, bsm : Dict):
        brake = bsm['bake_status']
        if len(str(brake)) > 5 or any([str(digit) not in ['0', '1'] for digit in brake]): 
            evidence = [bsm["full_bsm"]]
            # TODO: add encoding of reports
            self.reports.append(evidence)

    '''
    ############################################################
    Generic misbehavior functions
    '''

    def generateMbr(self, full_bsm : List):
        report = None
        # TODO: add encoding of reports
        return report

    # run_all_checks( List[JSON] ) => None
    # DESC: for every message, check for misbehavior
    def run_all_checks(self, bsm_json : List):
        for bsm in bsm_json:
            try: self.checkBrakeStatusError(bsm)
            except Exception as e: print(e)
    
    
