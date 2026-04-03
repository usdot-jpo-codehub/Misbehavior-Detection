### Faulty-BSM Generator

### Usage Instructions
#### Requirements
| Tool    | Description |
| -------- | ------- |
| Python 3.10+  | Python version    |
| requirements.txt | see **below** for installation of required Python packages     |
| data/keys/{bundle}    | certificate bundle for signing certificates. Required to run!   |

To run Faulty-Bsm-Generator, install the python requirements in `requirements.txt` by creating a virtual envrionment and installing libraries via pip. In the terminal navigate to the root of this repository (`./Misbehavior-Detection/faulty-bsm-generator`):
```
python3 -m venv ./venv
source venv/bin/activate
pip install -r requirements.txt
```

Note also the placement of the certificate bundle under `data/keys/`. The Faulty-BSM Generator signs every message: **the code will not run without a valid certificate bundle**. See below for the expected directory structure:

```
.
├── README.md
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

Where the necessary files for signing are found in
```
path_cert = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.cert"
path_s = f"./data/keys/{bundle}/download/{iValue}/{iValue}_{jValue}.s"
path_priv = f"./data/keys/{bundle}/dwnl_sgn.priv"
path_sgn_exp = f"./data/keys/{bundle}/sgn_expnsn.key"
```

FBSM Generator will search for a valid (non-expired) certificiate and sign if successful. See **Signing and Validation** for more information regarding validation of a signed message.

#### Example Running Faulty-BSM-Generator 
The primary test script for running Faulty-BSM Generator is ```src/test_faultybsm.py``` which enables a number of parameters for evaluation, including the **output codec** (--output_codec), **filename** (--input_file), and the number of random repitions per file (to generate new faults, --repeat_files). For example, reading an IeeeDot2Data object in ```data/example_IEEE/bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header```, perturbing it with one random fault, and writing in JSON codec:


```
python3 src/test_faultybsm.py --input_file bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header --repeat_files 1 --output_codec jer
```

where the output (in JER) will be written to ```output/``` and a corresponding line will be appended to ```output/log.csv``` (see below for more information). 

#### Note on Header Bytes
Our initial BSM data contained headers from WYDOT, which without intervention do not decode properly. Remove WYDOT headers by running `python src/utils/remove_WYDOT_header.py --input_file {COER_ENCODED_IEEE_DOT2_DATA_FILENAME}`. Recall that data should be placed in `data/example_IEEE`.

#### Random Seeds
Additionally, users can adjust the numpy random seed using ```--seed```, as in the following example


```python3 src/test_faultybsm.py --input_file bsmLogDuringEvent_1582235120_fe80__14dd_f8ff_fe5b_bac3.bin_no_header --repeat_files 1 --output_codec jer --seed 2025```


### Description 
Faulty-BSM-generator reads an encoded BSM, modifies it to include a randomly generated fault, writes the faulty BSM to a log, and finally encodes the BSM to a new format (XER, JER, COER, DER are supported). Currently, the following misbehaviors have been implemented:
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
|
└──requirements.txt
```

### Signing Messages and Validation
Messages are now signed via local certificates (`/data/keys/`) which can be validated with SCMS service (see `virtual-device/validate`). To do so, you'll need to make an account with SCMS and set the `API_KEY` envrionment variable. If validation of the signature is not required, set the parameter to false (`--validate False`). Validation is not required for signing. 
