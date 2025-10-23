from typing import List, Dict
import numpy as np 

from bsm_utils import MIN_DELAY_MILISEONDS
from misbehaviors.reportGenerator import ReportGenerator

class CheckFrequencyError(ReportGenerator):
    def __init__(self):
        reports = []
        target_class = "individual" 
    
    '''
    ############################################################
    # individualCheckFrequencyError( bsm : List[Dict], methods : str ) => None
    BSMs transmit at a maximum rate of 10 per second, or one every 100 
    milliseconds. This algorithm flags BSMs if the timestamp difference 
    between two concurrent BSMs is less than 100 milliseconds.  '''
    def individualCheckFrequencyError(self, bsm_list : List[Dict], method : str):
        # TODO: detemrine how to isolate BSMs by vehicle 
        # TODO: what format is the timestamp field?
        bsm_ts = np.array([bsm['timestamp'] for bsm in bsm_list])
        bsm_ts_diff = np.diff(bsm_ts)
        if any([cur_delay < MIN_DELAY_MILISEONDS for cur_delay in bsm_ts_diff]):
            evidence = bsm_list
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
    def run_all_checks(self, bsm_json : List[Dict]):
        try: self.individualCheckFrequencyError(bsm_json)
        except Exception as e: print(e)
    
    
