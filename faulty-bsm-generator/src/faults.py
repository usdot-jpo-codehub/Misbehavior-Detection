# internal imports
import bsm_utils
from bsm_encoder import parse_header
<<<<<<< HEAD
# type imports
from datetime import datetime
# data processing imports
import numpy as np
import copy
=======
# data processing imports
import numpy as np
import datetime

>>>>>>> 6613020 (added faults and signed messages)

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
        
<<<<<<< HEAD

=======
    test = 5
>>>>>>> 6613020 (added faults and signed messages)
    def load_faults(self):
        faults = []
        faults.append(Fault('no_fault', 'none', no_fault))
        # individual misbehaviors
        faults.append(Fault('perturb_acceleration', 'individual', perturb_acceleration))
<<<<<<< HEAD
        #faults.append(Fault('perturb_security_messageId', 'individual', perturb_security_messageId))
        #faults.append(Fault('perturb_speed', 'individual', perturb_speed))
        #faults.append(Fault('perturb_brake_status', 'individual', perturb_brake_status))
        #faults.append(Fault('perturb_location', 'list', perturb_location))
        #faults.append(Fault('perturb_heading', 'individual', perturb_heading))
=======
        faults.append(Fault('perturb_security_messageId', 'individual', perturb_security_messageId))
        faults.append(Fault('perturb_speed', 'individual', perturb_speed))
        faults.append(Fault('perturb_brake_status', 'individual', perturb_brake_status))
        faults.append(Fault('perturb_location', 'list', perturb_location))
        faults.append(Fault('perturb_heading', 'individual', perturb_heading))
>>>>>>> 6613020 (added faults and signed messages)
        
        # security misbehaviors 
        faults.append(Fault('perturb_security_message_id_inc_with_header_info', 'security', perturb_security_message_id_inc_with_header_info))
        faults.append(Fault('perturb_security_header_inc_with_security_profile', 'security', perturb_security_header_inc_with_security_profile))
<<<<<<< HEAD
        # faults.append(Fault('perturb_security_header_location_outside_certificate_validity', 'security', perturb_security_header_location_outside_certificate_validity))
        faults.append(Fault('perturb_security_header_psid_inc_with_certificate', 'security', perturb_security_header_psid_inc_with_certificate))
        # faults.append(Fault('perturb_security_header_time_outside_certificate_validity', 'security', perturb_security_header_time_outside_certificate_validity))
        # faults.append(Fault('perturb_security_message_inc_with_ssp', 'security', perturb_security_message_inc_with_ssp))
        # faults.append(Fault('perturb_security_message_location_outside_certificate_validity', 'security', perturb_security_message_location_outside_certificate_validity))
=======
        faults.append(Fault('perturb_security_header_location_outside_certificate_validity', 'security', perturb_security_header_location_outside_certificate_validity))
        faults.append(Fault('perturb_security_header_psid_inc_with_certificate', 'security', perturb_security_header_psid_inc_with_certificate))
        faults.append(Fault('perturb_security_header_time_outside_certificate_validity', 'security', perturb_security_header_time_outside_certificate_validity))
        faults.append(Fault('perturb_security_message_inc_with_ssp', 'security', perturb_security_message_inc_with_ssp))
        faults.append(Fault('perturb_security_message_location_outside_certificate_validity', 'security', perturb_security_message_location_outside_certificate_validity))
>>>>>>> 6613020 (added faults and signed messages)
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
<<<<<<< HEAD
    core_data = bsm['coreData']
    old_msg_id = core_data["messageId"] 
=======
    old_msg_id = bsm['messageId']
>>>>>>> 6613020 (added faults and signed messages)

    new_msg_id = np.random.randint(valid_id + 1, valid_id + 1000)
    bsm["messageId"] = new_msg_id
    return bsm, "perturb_security_messageId: set messageId to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_msg_id, OLD_VAL=old_msg_id)

def perturb_speed(bsm, speed_threshold=bsm_utils.MAX_SPEED):
    '''
    perturb_speed

    This algorithm flags BSMs with speed values over 100 miles per hour.  
    '''
<<<<<<< HEAD
    core_data = bsm['coreData']
=======
    core_data = bsm['value'][1]['coreData']
>>>>>>> 6613020 (added faults and signed messages)
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
<<<<<<< HEAD
    core_data = bsm['coreData']
    old_brake_status = core_data['brakes']['wheelBrakes']

    if np.random.rand() > 0.5: core_data['brakes']['wheelBrakes'] = str(np.random.randint(100000, 1000000))
    else: 
        digits = [str(np.random.randint(2, 9)) for _ in range(5)]
        brake_status = "".join(digits)
        core_data['brakes']['wheelBrakes'] = brake_status
=======
    core_data = bsm['value'][1]['coreData']
    old_brake_status = core_data['brakes']['wheelBrakes']

    core_data['brakes']['wheelBrakes'] = (np.random.randint(17, 99), np.random.randint(5, 8))#(np.random.randint())
>>>>>>> 6613020 (added faults and signed messages)

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
<<<<<<< HEAD
    core_data = bsm['coreData']
=======
    core_data = bsm['value'][1]['coreData']
>>>>>>> 6613020 (added faults and signed messages)

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
<<<<<<< HEAD
    core_data = bsm['coreData']
=======
    core_data = bsm['value'][1]['coreData']
>>>>>>> 6613020 (added faults and signed messages)
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
<<<<<<< HEAD
    headerInfo = IeeeDot2Data['content'][1]['tbsData']['headerInfo']

    profile_items = ['generationTime', 'psid']
    profile_index = np.random.randint(0, len(profile_items))
    profile_key = profile_items[profile_index]

    del headerInfo[profile_key]
    return bsm, "perturb_security_header_inc_with_security_profile: removed {NEW_VAL} from security headerInfo".format(\
        NEW_VAL=profile_key) 


def perturb_security_header_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
=======
    EPOCH_2004 = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)

    def __generate_Location():
        return {'latitude' : np.random.randint(-100, 100), \
                                                   'longitude' : np.random.randint(-100, 100), \
                                                   'elevation' : np.random.randint(0, 100)}
    def __generate_Expiry(generationTime):
        return int(generationTime + np.random.randint(0, 1000000))
    
    headerInfo = IeeeDot2Data['content'][1]['tbsData']['headerInfo']
    rand_int = np.random.randint(0, 3)

    new_field = None
    new_generationTime = int((datetime.datetime.now(datetime.timezone.utc) - EPOCH_2004).total_seconds())
    if rand_int == 0:
        new_field = 'generationLocation'
        headerInfo.update({'generationTime' : new_generationTime, \
                           'generationLocation' : __generate_Location() })
    elif rand_int == 1:
        new_field = 'expiryTime'
        headerInfo.update({'generationTime' : new_generationTime, \
                            'expiryTime' : __generate_Expiry(new_generationTime) }) 
    elif rand_int == 2:
        new_field = 'expiryTime + generationLocation'
        headerInfo.update({'generationTime' : new_generationTime, \
                           'generationLocation' : __generate_Location(), \
                            'expiryTime' : __generate_Expiry(new_generationTime) }) 
    
    return bsm, f"perturb_security_header_inc_with_security_profile: added {new_field} to security headerInfo"

def perturb_security_message_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
>>>>>>> 6613020 (added faults and signed messages)
    '''
    perturb_security_header_location_outside_certificate_validity

    Checks for fields in headerInfo as expected in J2945 
    '''
<<<<<<< HEAD

    signed_data = certificate["signedData"]
    header_loc = signed_data["headerInfo"]["generationLocation"]

    cert_locs = certificate["certificate"]["identifiedRegion"]
    if header_loc in cert_locs: cert_locs.remove(header_loc)
    return bsm, "perturb_security_header_location_outside_certificate_validity: removed {NEW_VAL} from locations in certificate".format(\
        NEW_VAL=header_loc) 
=======
    cert_region = certificate["toBeSigned"]["region"]
    cert_country = cert_region[1][0][1]
    code_str = f"{cert_country:03d}"

    # get invalid lat/long values
    pts = bsm_utils.get_coords_outside_region(code_str)
    # set message lat/lon to invalid coordinates
    bsm['value'][1]['coreData']['lat'] = pts[0]
    bsm['value'][1]['coreData']['long'] = pts[1]

    return bsm, "perturb_security_header_location_outside_certificate_validity: set lat/lon coordinates in message coreData to ({NEW_VAL}), outside of country designed by code {CODE}".format(\
        NEW_VAL=', '.join(map(str, pts)), CODE=code_str) 
>>>>>>> 6613020 (added faults and signed messages)


def perturb_security_header_psid_inc_with_certificate(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_psid_inc_with_certificate

    The psid in the security headerInfo is not contained in the appPermissions
    of the certificate, e.g., psid in the security headerInfo is equal to 32, but the appPermissions in the certificate does
    not include the value 32.
    '''

    signed_data = IeeeDot2Data['content'][1]['tbsData']['headerInfo']
<<<<<<< HEAD
    old_psid = certificate["toBeSigned"]["appPermissions"][0]["psid"]

    new_psid = old_psid + np.random.randint(1, 20)
    signed_data["psid"] = new_psid

    return bsm, "perturb_security_header_psid_inc_with_certificate: set psid in appPermissions to {NEW_VAL} from {OLD_VAL}".format(\
        NEW_VAL=new_psid, OLD_VAL=old_psid) 
=======
    cert_psid = certificate["toBeSigned"]["appPermissions"][0]["psid"]

    psid_delta = np.random.randint(1, 20)
    if np.random.uniform() > 0.5:
        new_psid = cert_psid + psid_delta
    else: 
        new_psid = cert_psid - psid_delta

    # set Ieee1609Dot2Data psid to faulty value
    signed_data["psid"] = new_psid

    return bsm, "perturb_security_header_psid_inc_with_certificate: set psid in appPermissions to {NEW_VAL} from {OLD_VAL} in certificate".format(\
        NEW_VAL=new_psid, OLD_VAL=cert_psid) 
>>>>>>> 6613020 (added faults and signed messages)


def perturb_security_header_time_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_header_time_outside_certificate_validity

    The generationTime in the security headerInfo is outside the
    validityPeriod in the certificate.
    '''
<<<<<<< HEAD
    
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
=======
    # validityPeriod[start] is # seconds since January 1, 2024
    validityPeriod = certificate["toBeSigned"]["validityPeriod"]
    
    cert_start_t = validityPeriod['start']
    cert_duration =  60 * validityPeriod['duration'][1] # hours to seconds
    cert_end_t = cert_start_t + cert_duration

    # randomly choose to assign IeeeDot2Data validity before or after certificate validity period
    rand_sec = np.random.randint(1, 1000)
    if np.random.uniform() > 0.5: 
        new_time = cert_end_t + rand_sec
    else: 
        new_time = cert_start_t - rand_sec

    # generationTime is the # microseconds since January 1, 2024
    old_time = IeeeDot2Data['content'][1]['tbsData']["headerInfo"]["generationTime"]
    IeeeDot2Data['content'][1]['tbsData']["headerInfo"]["generationTime"] = new_time * 1000000

    #test_cert_time_start = datetime(year=2004, month=1, day=1) + timedelta(seconds=cert_start_t)
    #test_cert_time_end = datetime(year=2004, month=1, day=1) + timedelta(seconds=cert_end_t)
    #test_ieee_time_old = datetime(year=2004, month=1, day=1) + timedelta(microseconds=old_time)
    #test_ieee_time_new = datetime(year=2004, month=1, day=1) + timedelta(microseconds=new_time * 1000000)

    return bsm, "perturb_security_header_time_outside_certificate_validity: transposed generationTime in headerInfo {NEW_VAL} seconds from certificate validityPeriod (from {OLD_VAL})".format(\
        NEW_VAL=rand_sec, OLD_VAL=old_time)  


# TODO: not sure we have access to SSP standards
>>>>>>> 6613020 (added faults and signed messages)
def perturb_security_message_inc_with_ssp(IeeeDot2Data, certificate, bsm):
    '''
    perturb_security_message_inc_with_ssp

    The message payload is inconsistent with the SSP in the certificate, as specified in
    SAE J3161/1 Appendix C, e.g., partII.supplementalVehicleExt.classDetails.role.police is present in the
    BasicSafetyMessage but the relevant SSP in the certificate does not permit DE_BasicVehicleRole to be set to
    police.
    '''
<<<<<<< HEAD

    pass

def perturb_security_message_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm):
    bsm_data = ['value'][1]['coreData']
    bsm_lat, bsm_lon = bsm_data['lat'], bsm_data['lon']

    certificate_region = certificate["certificate"]["region"]
    pass
=======
    emerg_roles = ["police", "ambulance", "fire"]
    rand_role = emerg_roles[np.random.randint(0, len(emerg_roles))]

    # check that certificate is not viable for police, ambulance, etc. role
    assert all([perm.get('ssp') is None for perm in certificate['toBeSigned']['appPermissions']])

    # set BSM payload to identify role illegally as polce, ambulance, etc. 
    certificate = certificate["toBeSigned"]
    new_role = {'partII-Value': (
      'SupplementalVehicleExtensions',
      {
        'classDetails': { 'role': rand_role }
      }
    )}
                  
    print(bsm) 
    bsm['value'][1]['partII'][0].pop('partII-Value', None)
    bsm['value'][1]['partII'][0]['partII-Id'] = 2
    bsm['value'][1]['partII'][0].update(new_role)


    print(bsm)

    return bsm, "perturb_security_message_inc_with_ssp: set BSM payload to identify as role ({NEW_VAL}), which is illegal for certificate without corresponding ssp permissions".format(\
        NEW_VAL=rand_role) 


# identify country by UN code
# use shapely or Geopandas to do spatial computation of the point within country borders 
def perturb_security_header_location_outside_certificate_validity(IeeeDot2Data, certificate, bsm, margin_deg=5):
    cert_region = certificate["toBeSigned"]["region"]
    cert_country = cert_region[1][0][1]

    code_str = f"{cert_country:03d}"
    pts = bsm_utils.get_coords_outside_region(code_str)
    
    IeeeDot2Data['content'][1]['tbsData']['headerInfo']['generationLocation'] = {'latitude' : pts[0], 'longitude': pts[1], 'elevation': 0 }
    return bsm, "perturb_security_message_location_outside_certificate_validity: set generationLocation in security header to ({NEW_VAL}), outside of country designed by code {CODE}".format(\
        NEW_VAL=', '.join(map(str, pts)), CODE=code_str) 
>>>>>>> 6613020 (added faults and signed messages)
    