from misbehaviors.reportGenerator import ReportGenerator

TGT_ID = 2
OBS_ID = 1

class SecurityMessageIdIncWithHeaderInfo(ReportGenerator):
    def __init__(self):
        self.tgt_id = TGT_ID
        self.obs_id = OBS_ID
        self.detections = [] 
    
    '''
    The messageId field of the MessageFrame as defined in SAE J2735 is inconsistent
    with the security headerInfo i.e. the messageId is not equal to basicSafetyMessage.
    '''
    def analyze_bsm(self, ieee, bsm, ieee_data):
        header_info = (
            ieee.get("content", {})
                .get("signedData", {})
                .get("tbsData", {})
                .get("headerInfo", {})
        )
        psid = header_info.get("psid")

        message_id = bsm.get("messageId")

        inconsistent = False
        if psid == 32 and message_id != 20:
            inconsistent = True
        elif psid is not None and psid != 32 and message_id == 20:
            inconsistent = True

        if inconsistent:
            print(f"DETECTION: MessageId {message_id} inconsistent with security headerInfo PSID {psid}")
            self.detections.append((self.tgt_id, self.obs_id, ieee_data))
        else:
            print("No inconsistency: MessageId aligns with security headerInfo PSID")

        return self.detections