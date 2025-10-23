# bsm_utils.py

# constants relevant to local misbehavior detection

'''
accelerationValueOutOfRange
########################################
ACCELERATION_THRESHOLD: Maximum acceleration defined 
ACCELERATION_UNAVAILABLE: Value of 2001 indicates longitudinal acceleration is not available
'''
ACCELERATION_THRESHOLD = 4002
ACCELERATION_UNAVAILABLE = 2001

'''
individualCheckLocationError 
########################################
LOC_DISTANCE_THRESHOLD: Maximum distance (L2) from grid center without violation 
MAX_MEDIAN_ENTRIES: Maximum number of logged median grid centers
'''
LOC_DISTANCE_THRESHOLD = 0
MAX_MEDIAN_ENTRIES = 10

'''
individualCheckSpeedError 
########################################
MAX_SPEED: Maximum distance (L2) from grid center without violation 
'''
MAX_SPEED = 100

'''
individualCheckHeadingError 
########################################
MAX_HEADING: Maximum value for 'heading' field
MIN_HEADING: Minimum value for 'heading' field
'''
MAX_HEADING = 360
MIN_HEADING = 0

'''
individualCheckFrequency
########################################
MIN_DELAY_MILISECONDS: Minimimum delay between BSMs of same vehicle (miliseconds)
'''
MIN_DELAY_MILISEONDS = 100


'''
securityHeaderIncWithSecurityProfile
########################################
'''
BSM_VALID_ID = 20