from typing import List, Dict

from bsm_utils import MAX_SPEED
from misbehaviors import ReportGenerator

class CheckSpeedError(ReportGenerator):
    def __init__(self):
        self.reports = []
        self.target_class = "individual" 
    
    '''
    ############################################################
    # checkSpeedError( bsm : Dict ) => None
    This algorithm flags BSMs with speed values over 100 miles per hour.  
    '''
    def checkSpeedError(self, bsm : Dict):
        speed = bsm['speed']
        if speed > MAX_SPEED or speed < 0: 
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
            try: self.checkSpeedError(bsm)
            except Exception as e: print(e)
    
    
