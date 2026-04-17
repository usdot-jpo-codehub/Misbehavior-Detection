# Faulty BSM Generator

The Faulty BSM Generator is an open-source Python tool that reads encoded Basic Safety Messages (BSMs), modifies them to include randomly generated faults, and encodes the BSMs to a new format (XER, JER, COER, DER are supported). 

## Directory Layout

```
data/                 # Sample encoded inputs 
└──keys/              # Certificate bundle containing signing keys
output/               # Generated outputs
src/                  # Decoding and modification logic
tests/                # Tests  
```

## Prerequisites

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage Instructions

Note the placement of the certificate bundle under `data/keys/`. As the Faulty BSM Generator signs every message, **the code will not run without a valid certificate bundle**. See below for the expected directory structure:

```
├── data/
│   ├── example_bsm/
│   └── example_IEEE/
|   └── keys/
|   |   ├── {bundle}/
|   |   |   ├── certchain/
|   |   |   └── download/
|   |   |   └── trustedcerts/   
|   |   |   └── dwnl_enc.priv
|   |   |   └── dwnl_sgn.priv
|   |   |   └── enc_expnsn.key
|   |   |   └── enr_sign.priv
|   |   |   └── sgn_expnsn.key
...
```

Where the necessary files for signing are found in:
```
path_cert = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.cert"
path_s = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.s"
path_priv = f"./data/keys/{bundle}/dwnl_sgn.priv"
path_sgn_exp = f"./data/keys/{bundle}/sgn_expnsn.key"
```

The tool will search for a valid (non-expired) certificiate and sign if successful. See **Signing Messages and Validation** for more information regarding validation of a signed message.

<<<<<<< HEAD
#### Example Running Faulty-BSM-Generator 
The primary test script for running Faulty-BSM Generator is ```src/test_faultybsm.py``` which enables a number of parameters for evaluation, including the **output codec** (--output_codec), **filename** (--input_file), and the number of random repitions per file (to generate new faults, --repeat_files). For example, reading an IeeeDot2Data object in ```data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header```, perturbing it with one random fault, and writing in JSON codec:
=======
### Example Running Faulty BSM Generator 
The primary test script for running Faulty BSM Generator is ```src/test_faultybsm.py``` which enables a number of parameters for evaluation, including the **output codec** (--output_codec), **filename** (--input_file), and the number of random repitions per file (to generate new faults, --repeat_files). For example, reading an IeeeDot2Data object in ```data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header```, perturbing it with one random fault, and writing in JSON codec:


>>>>>>> 69ada860a9508b1ad3063020b24ecfbf2e2c5d1a
```
python3 src/test_faultybsm.py --input_file bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header --repeat_files 1 --output_codec jer
```

where the output (in JER) will be written to ```output/``` and a corresponding line will be appended to ```output/log.csv``` (see below for more information). 

<<<<<<< HEAD
#### Integration and Running with the JPO-ODE 
The Faulty BSM Generator can inget messages through the ODE, and additionally, publish its modified messages to it as well. To do so, clone the compatible [jpo-ode fork](https://github.com/Stephen-Noblis/jpo-ode-FBSM) and follow the instructions for building and running the containers. Navigate to the root of this directory and run the `inject_through_ode` script:
```
python ./src/inject_through_ode.py
```
Running this script requires following the same procudes above (see _Requirements_). If connection is succesful, you should see the following confirmation and idle messages:
```
topic=topic.OdeBsmJson partition=0 offset=175
No message yet...
```

If a BSM passes through the JPO-ODE, you should be able to see it. We include a teat file (/src/utils/send_bsm.py) that connects to the JPO-ODE and sends a BSM. If a message *is* encountered by the FBSM, the log and output directory should update with the new message, and a sending message should appear:
```
====================================================================================================
topic=topic.OdeBsmJson partition=0 offset=174

Trying UDP target IP: {YOUR_SERVER_IP}
✓ Sent 376 bytes successfully to {YOUR_SERVER_IP}
Check ODE logs now with: docker compose -f jpo-ode/docker-compose.yml logs --tail 20 ode

====================================================================================================
```


#### Note on Header Bytes
=======
### Note on Header Bytes
>>>>>>> 69ada860a9508b1ad3063020b24ecfbf2e2c5d1a
Our initial BSM data contained headers from WYDOT, which without intervention do not decode properly. Remove WYDOT headers by running `python src/utils/remove_WYDOT_header.py --input_file {COER_ENCODED_IEEE_DOT2_DATA_FILENAME}`. Recall that data should be placed in `data/example_IEEE`.

### Random Seeds
Additionally, users can adjust the numpy random seed using ```--seed```, as in the following example:


```python3 src/test_faultybsm.py --input_file bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header --repeat_files 1 --output_codec jer --seed 2025```


## Supported Misbehaviors 
Currently, the following misbehaviors have been implemented:
- **perturb_security_message_id_inc_with_header_info**: This algorithm generates a random string for the MessageFrame messageID
- **perturb_security_header_inc_with_security_profile**: The security headerInfo is inconsistent with the security profile specified in SAE J2945/1 section 6.1.2.2 as referred to from SAE J3161/1 section 6.1.2, e.g., generationTime is absent in the security headerInfo but is required to be present in the security profile.
- **perturb_security_message_location_outside_certificate_validity**: set lat/lon coordinates in message coreData outside of country designed by code
- **perturb_security_header_psid_inc_with_certificate**: The psid in the security headerInfo is not contained in the appPermissions of the certificate
- **perturb_security_header_time_outside_certificate_validity**: The generationTime in the security headerInfo is outside the validityPeriod in the certificate
- **perturb_security_message_inc_with_ssp**: The message payload is inconsistent with the SSP in the certificate, as specified in SAE J3161/1 Appendix C, e.g., partII.supplementalVehicleExt.classDetails.role.police is present in the BasicSafetyMessage but the relevant SSP in the certificate does not permit DE_BasicVehicleRole to be set to police.
- **perturb_security_header_location_outside_certificate_validity**: location in security header is ooutside the bounds indicated by the certificate
- **perturb_acceleration**: set the longitudinal acceleration to some random value exceeding the valid threshold
- **perturb_speed**: set speed (BSM value) over 100 miles per hour
- **perturb_brake_status**: set to value greater than 5 digits OR (randomly decided) set digit to neither 1 nor 0
- **perturb_heading**: set heading value some integer greater than 360 degrees
- **perturb_location**: set location of vehicle from one message outside the plausible boundaries implied by accompanying messages
- **perturb_security_messageId**: set the message_Id field to some value not equal to 20



A misbehavior is selected at random (via a random seed process to enable reproduction), the BSM is modified, and a fault-log (output/log.csv) is appended to with the following information:
- **BSM_id**: id of the new BSM. The modified BSM will be output with the following format (output/{encoded_out_BSM_id})
- **fault_id**: id of the fault/misbehavior (*perturb_acceleration*, etc.) assigned to the BSM
- **fault_desc**: description of what modification took place. An example description: "*perturb_speed: set speed to 835 from 0*"
- **date**: the datetime at which the modified BSM was produced.
An example entry is provided below:
``` 
bsm_id,fault_id,fault_desc,date 
0,2,perturb_speed: set speed to 835 from 0,2025-03-18 13:28:08.888684 
```

<<<<<<< HEAD
### Repository Structure
```
.
├── README.md
├── data/
│   ├── example_bsm/
│   └── example_IEEE/
|   └── keys/
├── output/
├── src/
│   ├── utils/
|   │   ├── asn/
|   |   |   ├── Ieee1609Dot2.py
|   |   |   ├── J2735.py
|   |   └── bsm_utils.py
|   |   └── constants.py
|   |   └── remove_WYDOT_header.py
│   └── test_faultybsm.py
|   └── faulty_bsm_generator.py
|   └── faults.py
|   └── fault_log.py
|   └── data_signer.py
|   └── bsm_encoder.py
|   └── inject_through_ode.py
|
└──requirements.txt
```
=======
>>>>>>> 69ada860a9508b1ad3063020b24ecfbf2e2c5d1a

## Signing Messages and Validation
Messages are now signed via local certificates (`/data/keys/`) which can be validated with SCMS service (see `virtual-device/validate`). To do so, you'll need to make an account with SCMS and set the `API_KEY` envrionment variable. If validation of the signature is not required, set the parameter to false (`--validate False`). Validation is not required for signing. 
