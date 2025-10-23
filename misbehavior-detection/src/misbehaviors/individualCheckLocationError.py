from typing import List, Dict
from os import scandir, mkdir, path
import numpy as np
import json

from utils import RECORDINGS_DIR
from bsm_utils import MAX_MEDIAN_ENTRIES, LOC_DISTANCE_THRESHOLD
from misbehaviors.reportGenerator import ReportGenerator

LOCATION_MEDIAN_FILE = "medianLocationLog.json"

class CheckLocationError(ReportGenerator):
    def __init__(self):
        self.reports = []
        self.target_class = "individual" 
        
        self.medianCenters = []
        # if there's no file with the median location measurements, make one
        if LOCATION_MEDIAN_FILE in scandir(RECORDINGS_DIR):
            fd = open(path.join(RECORDINGS_DIR, LOCATION_MEDIAN_FILE), 'r')
            self.medianCenters = [json.load(line) for line in fd.readlines()]
        else: mkdir(path.join(RECORDINGS_DIR, LOCATION_MEDIAN_FILE))

    
    '''
    ############################################################
    # checkLocationError( bsm : Dict ) => None
    A vehicle’s location is analyzed with reference to the reported locations of every vehicle 
    transmitting to the same roadside unit. The simulator replicates this environment by dividing BSMs 
    into square regions bounded by X and Y coordinates, each of which represent a hypothetical roadside unit’s 
    reception radius. Each region has a unique grid cell ID, which the Faulty BSM Generator preassigns to each 
    BSM before modifying it. The length of one side of these grid cells is specified by the "grid_diameter” 
    field in the control file. 
    '''
    def checkLocationError(self, bsm_list : List[Dict], method : str):
        '''
        Designate a "central point" within a grid cell using the aggregate of all reported positions within the 
        cell. BSMs reporting a distance that are considerably far away from this central point will be flagged with
        misbehavior. 
        '''
        center = None
        X_coords = np.array([bsm['latitude'] for bsm in bsm_list])
        Y_coords = np.array([bsm['longitude'] for bsm in bsm_list])
        if method == "mean": center = np.array([np.mean(X_coords), np.mean(Y_coords)])
        elif method == "median": center = np.array([np.median(X_coords), np.median(Y_coords)])
        elif method == "median_of_median": 
            X_median_coords = [coord[0] for coord in self.medianCenters]
            Y_median_coords = [coord[1] for coord in self.medianCenters]
            X_median_coords.append(np.median(X_coords))
            Y_median_coords.append(np.median(Y_coords))

            # if exceeding the number of logged centers, drop, 
            center = np.array([np.median(X_median_coords), np.median(Y_median_coords)])
            if center.shape[0] > MAX_MEDIAN_ENTRIES: center = center[-MAX_MEDIAN_ENTRIES:]

        else: raise Exception("'method' must be in [mean, median, median_of_median]")
        
        coords = np.vstack((X_coords, Y_coords))
        # check all points against center (currently L2 norm)
        error = np.sqrt(np.sum(np.square(coords - center), axis=1), axis=1)
        if np.any(error > LOC_DISTANCE_THRESHOLD): 
            evidence = bsm_list
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
        try: self.individualCheckFrequencyError(bsm_json)
        except Exception as e: print(e)
    
    
