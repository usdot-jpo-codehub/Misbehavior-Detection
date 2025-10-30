### Faulty-BSM Generator

### Usage Instructions
#### Requirements
To run Faulty-Bsm-Generator, install the python requirements in /requirements.txt by creating a virtual envrionment and installing libraries via pip. In the terminal navigate to the root of this repository (./Misbehavior-Detection/faulty-bsm-generator):
```
python3 -m venv ./venv
pip install -r requirements.txt
```

#### Scripts and Running Faulty-BSM-Generator 
The primary test script for running Faulty-BSM Generator is ```src/test_faultybsm.py``` which enables a number of parameters for evaluation, including the **output codec** (--output_codec), **filename** (--input_file), and the number of random repitions per file (to generate new faults, --repeat_files). For example, reading an IeeeDot2Data object in ```data/example_IEEE/test_IeeeDot2Data.bin```, perturbing it with one random fault, and writing it's MessageFrame in JSON codec:


```python3 src/test_faultybsm.py --input_file test_IeeeDot2Data.bin --repeat_files 1 --output_codec jer --object_out MessageFrame```

where the output (in JER) will be written to ```output/``` and a corresponding line will be appended to ```output/log.csv``` (see below for more information). 

#### Note on Header Bytes
Validation of Faulty-BSM-Generator depended on test BSMs which included 26 header bytes prepended to the MessageFrame structure (see 'decode_bsm' in ./src/bsm_encoder.py). Therefore, BSMs which do not include these header bytes may cause failure in this decoding function.  

#### Random Seeds
Additionally, users can adjust the numpy random seed using ```--seed```, as in the following example


```python3 src/test_faultybsm.py --input_file test_IeeeDot2Data.bin --repeat_files 1 --output_codec jer --object_out MessageFrame --seed 2025```


### Description 
Faulty-BSM-generator reads an encoded BSM, modifies it to include a randomly generated fault, writes the faulty BSM to a log, and finally encodes the BSM to a new format (XER, JER, COER, DER are supported). Currently, the following misbehaviors have been implemented:
- **perturb_acceleration**: set the longitudinal acceleration to some random value exceeding the valid threshold
- **perturb_speed**: set speed (BSM value) over 100 miles per hour
- **perturb_brake_status**: set to value greater than 5 digits OR (randomly decided) set digit to neither 1 nor 0
- **perturb_heading**: set heading value some integer greater than 360 degrees

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
├── output/
├── src/
│   ├── asn/
|       ├── Ieee1609Dot2.py
|       ├── J2735.py
│   └── test_faultybsm.py
|   └── faulty_bsm_generator.py
|   └── faults.py
|   └── fault_log.py
|   └── constants.py
|   └── bsm_utls.py
|   └── bsm_enconder.py
|
└──requirements.txt

#### Next Steps
- Certificate tests need work
- Separate test scripts from src code