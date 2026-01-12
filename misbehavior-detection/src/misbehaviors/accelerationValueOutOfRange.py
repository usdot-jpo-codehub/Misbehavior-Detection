from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 5
OBS_ID = 4
ACCELERATION_THRESHOLD = 2001

class AccelerationValueOutOfRange(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 
 
    # DESC: coreData.accelSet.long, considered as an integer, encodes a value greater than 4002.
    def analyze_bsm(self, ieee, bsm, ieee_data):
        acceleration = bsm["value"]["BasicSafetyMessage"]["coreData"]["accelSet"]["long"]
        if acceleration > ACCELERATION_THRESHOLD: 
            print(f"DETECTION: Acceleration value out of range detected: {acceleration}")
            self.detections.append((self.tgt_id, self.obs_id, ieee_data))
        else:
            print(f"No Acceleration value out of range detected: {acceleration}")
        return self.detections