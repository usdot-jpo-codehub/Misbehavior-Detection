# internal imports
import bsm_utils
from bsm_encoder import parse_header
# type imports
from datetime import datetime
# data processing imports
import numpy as np
import copy

class FaultGenerators:
    def __init__(self, include_gens=['none', 'individual', 'security']):
        all_faults = self.load_faults()

        filtered_faults = []
        for fault in all_faults:
            if fault.type == "none": filtered_faults.append(fault)
            if fault.type in include_gens: filtered_faults.append(fault)
            if fault.name in include_gens: filtered_faults.append(fault)
        
        

        if len(filtered_faults) == 0: raise Exception("No Faults (type / name) matched the criteria in {FAULT_LIST}"\
                                                      .format(FAULT_LIST=''.join(include_gens)))
        self.faults = filtered_faults
        

    def load_faults(self):
        faults = []
        faults.append(Fault('no_fault', 'none', no_fault))
        # individual misbehaviors
        faults.append(Fault('perturb_acceleration', 'individual', perturb_acceleration))
        #faults.append(Fault('perturb_security_messageId', 'individual', perturb_security_messageId))
        #faults.append(Fault('perturb_speed', 'individual', perturb_speed))
        #faults.append(Fault('perturb_brake_status', 'individual', perturb_brake_status))
        #faults.append(Fault('perturb_location', 'list', perturb_location))
        #faults.append(Fault('perturb_heading', 'individual', perturb_heading))
        
        # security misbehaviors 
        faults.append(Fault('perturb_security_message_id_inc_with_header_info', 'security', perturb_security_message_id_inc_with_header_info))
        faults.append(Fault('perturb_security_header_inc_with_security_profile', 'security', perturb_security_header_inc_with_security_profile))
        # faults.append(Fault('perturb_security_header_location_outside_certificate_validity', 'security', perturb_security_header_location_outside_certificate_validity))
        faults.append(Fault('perturb_security_header_psid_inc_with_certificate', 'security', perturb_security_header_psid_inc_with_certificate))
        # faults.append(Fault('perturb_security_header_time_outside_certificate_validity', 'security', perturb_security_header_time_outside_certificate_validity))
        # faults.append(Fault('perturb_security_message_inc_with_ssp', 'security', perturb_security_message_inc_with_ssp))
        # faults.append(Fault('perturb_security_message_location_outside_certificate_validity', 'security', perturb_security_message_location_outside_certificate_validity))
        return faults

class Fault:
    def __init__(self, fault_name, fault_type, fault_func):
        self.name = fault_name
        self.type = fault_type
        self.func = fault_func

'''
misbehavior perturbation functions
-----------------------------------
'''

def no_fault(bsm):
    '''
    no_fault

    no values changed. BSM is presumed valid.
    '''

    return bsm, "no fault"


'''
(I) INDIVIDUAL MISBEHAVIORS
'''
def perturb_acceleration(bsm, accel_threshold=bsm_utils.ACCELERATION_THRESHOLD, accel_max=bsm_utils.ACCELERATION_MAX):
    '''
    perturb_acceleration

    set the longitudinal acceleration to some random value exceeding the valid threshold
    '''
    # parse the bsm object
    accel_val = np.random.randint(2001, 2020)
    core_data = bsm['value'][1]['coreData']

    cur_long_accel = core_data['accelSet']["long"]
    core_data['accelSet']["long"] = accel_val
    
    return bsm, "perturb_acceleration: replaced longitudinal acceleration {OLD_VAL} value with illegal value {OFFSET}".format(\
       OLD_VAL=cur_long_accel, OFFSET=accel_val)
    
def perturb_security_messageId(bsm, valid_id=bsm_utils.VALID_ID):
    '''
    perturb_security_messageId

    set the message_Id field to some value not equal to 20
    '''
    core_data = bsm['coreData']
    old_msg_id = core_data["messageId"] 

    new_msg_id = np.random.randint(valid_id + 1, valid_id + 1000)
    bsm["messageId"] = new_msg_id
    return bsm, "perturb_security_messageId: set messageId to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_msg_id, OLD_VAL=old_msg_id)

def perturb_speed(bsm, speed_threshold=bsm_utils.MAX_SPEED):
    '''
    perturb_speed

    This algorithm flags BSMs with speed values over 100 miles per hour.  
    '''
    core_data = bsm['coreData']
    old_speed = core_data["speed"]
    # compute and set faulty speed
    new_speed =  np.random.randint(speed_threshold + 1, speed_threshold + 1000)
    core_data["speed"] = new_speed

    return bsm, "perturb_speed: set speed to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_speed, OLD_VAL=old_speed)

def perturb_brake_status(bsm):
    '''
    perturb_brake_status

    This algorithm flags BSMs with improper brake status format by checking 
    '''
    core_data = bsm['coreData']
    old_brake_status = core_data['brakes']['wheelBrakes']

    if np.random.rand() > 0.5: core_data['brakes']['wheelBrakes'] = str(np.random.randint(100000, 1000000))
    else: 
        digits = [str(np.random.randint(2, 9)) for _ in range(5)]
        brake_status = "".join(digits)
        core_data['brakes']['wheelBrakes'] = brake_status

    new_brake_status = core_data['brakes']['wheelBrakes']
    return bsm, "perturb_brake_status: set bake_status to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_brake_status, OLD_VAL=old_brake_status)

def perturb_location(bsm_list, dist_threshold=bsm_utils.LOC_DISTANCE_THRESHOLD):
    '''
    perturb_location

    A vehicle’s location is analyzed with reference to the reported locations of every vehicle 
    '''
    bsm_index = np.random.randint(0, len(bsm_list))
    loc_field = None
    if np.random.rand() > 0.5: loc_field = 'latitude'
    else: loc_field = 'longitude'
    
    bsm = bsm_list[bsm_index]
    core_data = bsm['coreData']

    old_loc = core_data[loc_field]
    new_loc = core_data[loc_field][loc_field] + np.random.randint(dist_threshold, dist_threshold + 100)
    bsm_list[bsm_index][loc_field] = new_loc

    return bsm, "perturb_location: set location {LAT_OR_LON} to {NEW_VAL} from {OLD_VAL}".format(\
        LAT_OR_LON =loc_field, NEW_VAL=new_loc, OLD_VAL=old_loc)

def perturb_heading(bsm, min_val=bsm_utils.MIN_HEADING, max_val=bsm_utils.MAX_HEADING):
    '''
    perturb_heading

    This algorithm flags BSMs with impossible heading values outside of the 
    range of 0 to 360 degrees.
    '''
    core_data = bsm['coreData']
    old_heading = core_data['heading']

    new_heading = np.random.randint(low=max_val + 1, high=max_val + 1000)
    core_data['heading'] = new_heading

    return bsm, "perturb_heading: set heading to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_heading, OLD_VAL=old_heading)

'''
(II) SECURITY MISBEHAVIORS
'''

def perturb_security_message_id_inc_with_header_info(IeeeDot2Data, certificate, bsm, bsm_id=bsm_utils.VALID_ID):
    '''
    perturb_security_message_id_inc_with_header_info

    This algorithm generates a random string for the MessageFrame messageID
    '''
    old_msg_id = bsm['messageId']

    new_msg_id = np.random.randint(0, bsm_id)
    bsm['messageId'] = new_msg_id
    return bsm, "perturb_security_message_id_inc_with_header_info: set messageId to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_msg_id, OLD_VAL=old_msg_id) 


def perturb_security_header_inc_with_security_profile(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_inc_with_security_profile

    The security headerInfo is inconsistent with the security profile specified in
    SAE J2945/1 section 6.1.2.2 as referred to from SAE J3161/1 section 6.1.2, e.g., generationTime is absent in the
    security headerInfo but is required to be present in the security profile.
    '''
    headerInfo = IeeeDot2Data['content'][1]['tbsData']['headerInfo']

    profile_items = ['generationTime', 'psid']
    profile_index = np.random.randint(0, len(profile_items))
    profile_key = profile_items[profile_index]

    del headerInfo[profile_key]
    return bsm, "perturb_security_header_inc_with_security_profile: removed {NEW_VAL} from security headerInfo".format(\
        NEW_VAL=profile_key) 


def perturb_security_header_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_location_outside_certificate_validity

    Checks for fields in headerInfo as expected in J2945 
    '''

    signed_data = certificate["signedData"]
    header_loc = signed_data["headerInfo"]["generationLocation"]

    cert_locs = certificate["certificate"]["identifiedRegion"]
    if header_loc in cert_locs: cert_locs.remove(header_loc)
    return bsm, "perturb_security_header_location_outside_certificate_validity: removed {NEW_VAL} from locations in certificate".format(\
        NEW_VAL=header_loc) 


def perturb_security_header_psid_inc_with_certificate(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_psid_inc_with_certificate

    The psid in the security headerInfo is not contained in the appPermissions
    of the certificate, e.g., psid in the security headerInfo is equal to 32, but the appPermissions in the certificate does
    not include the value 32.
    '''

    signed_data = IeeeDot2Data['content'][1]['tbsData']['headerInfo']
    old_psid = certificate["toBeSigned"]["appPermissions"][0]["psid"]

    new_psid = old_psid + np.random.randint(1, 20)
    signed_data["psid"] = new_psid

    return bsm, "perturb_security_header_psid_inc_with_certificate: set psid in appPermissions to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_psid, OLD_VAL=old_psid) 


def perturb_security_header_time_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_time_outside_certificate_validity

    The generationTime in the security headerInfo is outside the
    validityPeriod in the certificate.
    '''
    
    dur_start = certificate["toBeSigned"]["validityPeriod"]["start"]
    dur_hrs = certificate["toBeSigned"]["validityPeriod"]["duration"][1]

    old_time = datetime.fromtimestamp(dur_start)
    
    cert_start_t = datetime.fromtimestamp(certificate["certificate"]['validityPeriod']['start'])
    cert_duration =  datetime.hour(certificate["certificate"]['validityPeriod']['duration'])
    cert_end_t = cert_start_t + cert_duration

    new_time = cert_end_t + np.random.int(1, 500)
    signed_data["headerInfo"]["generationTime"] = new_time

    return bsm, "perturb_security_header_time_outside_certificate_validity: set psid in appPermissions to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_time, OLD_VAL=old_time) 


# TODO: not sure I have access to SSP standards
def perturb_security_message_inc_with_ssp(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_message_inc_with_ssp

    The message payload is inconsistent with the SSP in the certificate, as specified in
    SAE J3161/1 Appendix C, e.g., partII.supplementalVehicleExt.classDetails.role.police is present in the
    BasicSafetyMessage but the relevant SSP in the certificate does not permit DE_BasicVehicleRole to be set to
    police.
    '''

    pass

def perturb_security_message_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
    bsm_data = ['value'][1]['coreData']
    bsm_lat, bsm_lon = bsm_data['lat'], bsm_data['lon']

    certificate_region = certificate["certificate"]["region"]
    pass
    