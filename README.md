# Misbehavior Detection

# README Outline:
* Project Description
* Prerequisites
* Usage
* Version History and Retention
* License
* Contact Information
* Acknowledgements

# Project Description

The ITS JPO Misbehavior Detection project is designed to detect misbehavior in SAE J2735 Basic Safety Messages (BSM) as defined by SAE J3287. The first release includes two tools: the Faulty BSM Generator and the Misbehavior Detection tool. The Faulty BSM Generator takes existing ASN.1 encoded BSMs, decodes them, modifies the acceleration value to one out of range at a randome rate, and re-encodes the BSM. The Faulty BSM Generator also maintains a log that allows for easy traceability of BSMs with misbehavior for misbehavior detection testing. The Misbehavior Detection tool takes ASN.1 encoded BSMs as input, decodes them, checks if the accleration value is out of range and if so, generates and encodes an SAE J3287 defined misbehavior detection report. All encoding and decoding is accomplished with ASN.1C with some slight modifications to the ASN.1 definitions to remove parameterization and other advanced patterns not supported by ASN.1C. Planned future minor releases include adding Security Credential Management System (SCMS) certificate signing and integration with the Operational Data Environment (ODE). Planned future major releases include adding an experimental mode with misbehavior detection beyond what is defined in SAE J3287.  

* [Misbehavior Detection and Reporting Tool README](https://github.com/usdot-jpo-codehub/Misbehavior-Detection/blob/main/misbehavior-detection/README.md)
* [Faulty BSM Generator README](https://github.com/usdot-jpo-codehub/Misbehavior-Detection/tree/main/faulty-bsm-generator)

# Prerequisites

See individual READMEs in each tool folder for the prerequisites for that tool.

# Usage
See individual READMEs in each tool folder for the usage instructions for that tool.

# Version History and Retention
**Status:** This project is in the release phase.

**Release Frequency:** This project will be updated approximately once a month

**Release History:** Version 1.0 Released 10/29/2025 - Faulty BSM Generator and Misbehavior Detection with ASN.1 Encoding and Decoding

**Retention:** This project will remain publicly accessible for a minimum of five years (until at least 06/15/2025).

# Contact Information
Contact Name: Justin Anderson
Contact Information: justin.anderson@dot.gov

# Acknowledgements

## Citing this code
To track how this government-funded code is used, we request that if you decide to build additional software using this code please acknowledge it in your software's README/documentation.

To cite this code in a publication or report, please cite our associated report/paper and/or our source code. Below is a sample citation for this code:

_`ITS JPO`. (`2025`)._ `Misbehvaior Detection` _(`1.0`) [Source code]. Provided by ITS CodeHub through GitHub.com. Accessed YYYY-MM-DD from `https://github.com/usdot-jpo-codehub/Misbehavior-Detection/tree/main`._

When you copy or adapt from this code, please include the original URL you copied the source code from and date of retrieval as a comment in your code.
