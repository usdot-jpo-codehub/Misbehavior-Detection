# utils.py
from misbehaviors import accelerationValueOutOfRange, securityHeaderIncWithSecurityProfile, securityHeaderLocationOutsideCertificateValidity, \
securityHeaderPsidIncWithCertificate, securityHeaderTimeOutsideCertificateValidity, securityMessageIdIncWithHeaderInfo, \
securityMessageIncWithSsp, securityMessageLocationOutsideCertificateValidity 
from os import path

# directory paths
DATA_DIR = "resources"
CERT_DIR = path.join(DATA_DIR, "certificates")
BSM_DIR = path.join(DATA_DIR, "messages")
RECORDINGS_DIR = path.join(DATA_DIR, "recordings")

OBS_TITLES = { "acceleration-ValueOutofRange" : accelerationValueOutOfRange.AccelerationValueOutOfRange(), \
                 "security-HeaderIncWithSecurityProfile" : securityHeaderIncWithSecurityProfile.SecurityHeaderIncWithSecurityProfile(), \
                 "security-HeaderLocationOutsideCertificateValidity" : securityHeaderLocationOutsideCertificateValidity.SecurityHeaderLocationOutsideCertificateValidity(), \
                 "security-HeaderPsidIncWithCertificate": securityHeaderPsidIncWithCertificate.SecurityHeaderPsidIncWithCertificate(), \
                 "security-HeaderTimeOutsideCertificateValidity.py": securityHeaderTimeOutsideCertificateValidity.SecurityHeaderTimeOutsideCertificate(), \
                 "security-MessageIdIncWithHeaderInfo": securityMessageIdIncWithHeaderInfo.SecurityMessageIfIncWithHeaderInfo(),\
                 "security-MessageIncWithSsp": securityMessageIncWithSsp.SecurityMessageIncWithSsp(), \
                 "security-MessageLocationOutsideCertificateValidity": securityMessageLocationOutsideCertificateValidity.SecurityMessageLocationOutsideCertificateValidity()}