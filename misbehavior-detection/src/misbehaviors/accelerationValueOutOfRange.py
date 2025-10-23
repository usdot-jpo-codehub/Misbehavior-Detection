from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 5
OBS_ID = 4
ACCELERATION_THRESHOLD = 2001

class AccelerationValueOutOfRange(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 
 
    ############################################################
    # accelerationValueOutOfRange
    # DESC: coreData.accelSet.long, considered as an integer, encodes a value greater than 4002.
    def analyze_bsm(self, bsm, bsm_hex):
        acceleration = bsm["value"]["BasicSafetyMessage"]["coreData"]["accelSet"]["long"]
        print("Accel:" + str(acceleration))
        if acceleration > ACCELERATION_THRESHOLD: 
            self.detections.append((self.tgt_id, self.obs_id, bsm_hex))
        return self.detections
    ############################################################