from typing import List, Dict

from bsm_utils import MAX_HEADING, MIN_HEADING
from misbehaviors.reportGenerator import ReportGenerator

class CheckHeadingError(ReportGenerator):
    def __init__(self):
        self.reports = []
        self.target_class = "individual" 
    
    '''
    ############################################################
    # checkSpeedError( bsm : Dict ) => None
    This algorithm flags BSMs with impossible heading values outside of the 
    range of 0 to 360 degrees.      '''
    def checkHeadingError(self, bsm : Dict):
        heading = bsm['heading']
        if heading > MAX_HEADING or heading < MIN_HEADING: 
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
            try: self.checkHeadingError(bsm)
            except Exception as e: print(e)
    
    
