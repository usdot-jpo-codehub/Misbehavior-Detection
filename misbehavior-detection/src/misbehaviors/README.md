### Misbehavior-Detection -- Algorithms 

This directory implements algorithms outlined in the SAE J3287 standard
- **Acceleration-ValueOutOfRange:** The coreData.accelSet.long, considered as an integer, encodes a value greater than 4002.
- **Security-MessageIdIncWithHeaderInfo:** The messageId field of MessageFrame as defined in SAE J2735 is inconsistent with the security headerInfo, i.e., the messageId is not equal to basicSafetyMessage
- **Security-HeaderIncWithSecurityProfile:** The security headerInfo is inconsistent with the security profile specified in SAE J2945/1 section 6.1.2.2 as referred to from SAE J3161/1 section 6.1.2, e.g., generationTime is absent in the security headerInfo but is required to be present in the security profile. 
- **Security-HeaderPsidIncWithCertificate:** The psid in the security headerInfo is not contained in the appPermissions of the certificate, e.g., psid in the security headerInfo is equal to 32, but the appPermissions in the certificate does not include the value 32.
- **Security-MessageIncWithSsp:** The message payload is inconsistent with the SSP in the certificate, as specified in SAE J3161/1 Appendix C, e.g., partII.supplementalVehicleExt.classDetails.role.police is present in the BasicSafetyMessage but the relevant SSP in the certificate does not permit DE_BasicVehicleRole to be set to police. 
- **Security-HeaderTimeOutsideCertificateValidity:** The generationTime in the security headerInfo is outside the validityPeriod in the certificate.
- **Security-MessageLocationOutsideCertificateValidity:** The coreData.lat and/or coreData.long of BasicSafetyMessage is outside the region in the certificate.
- **Security-HeaderLocationOutsideCertificateValidity:** The generationLocation in the security headerInfo is outside the region in the certificate.