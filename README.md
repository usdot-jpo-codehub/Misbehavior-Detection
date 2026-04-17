# Misbehavior Detection

The ITS JPO Misbehavior Detection project is designed to detect misbehavior in SAE J2735 Basic Safety Messages (BSM) as defined by SAE J3287. This release includes two tools: the Faulty BSM Generator and the Misbehavior Detection and Reporting tool. 

The Faulty BSM Generator decodes existing ASN.1 encoded BSMs, modifies the contents to introduce misbehavior, and re-encodes the BSM. The Faulty BSM Generator also maintains a log that allows for easy traceability of BSMs with misbehavior for misbehavior detection testing. 

The Misbehavior Detection tool takes ASN.1 encoded BSMs as input and checks for the presence any SAE J3287 defined misbehavior(s). If any misbehaviors are detected, the tool generates and encodes an SAE J3287 defined misbehavior detection report. All encoding and decoding is accomplished with asn1c with modifications to the ASN.1 definitions to remove parameterization and other advanced patterns not supported by asn1c. 

Planned future releases include integration with the Operational Data Environment (ODE) and adding an experimental mode with misbehavior detection beyond what is defined in SAE J3287.  

# Prerequisites and Usage

See individual READMEs in each tool folder for the prerequisites for that tool.

* [Misbehavior Detection and Reporting Tool README](https://github.com/usdot-jpo-codehub/Misbehavior-Detection/blob/main/misbehavior-detection/README.md)
* [Faulty BSM Generator README](https://github.com/usdot-jpo-codehub/Misbehavior-Detection/tree/main/faulty-bsm-generator)

# Version History and Retention
**Status:** This project is in the release phase.

**Release History:** 

Version 1.0 Released 10/29/2025 - Faulty BSM Generator and Misbehavior Detection with ASN.1 Encoding and Decoding

Version 2.0 Released 04/02/2026 - Added misbehavior report signing and encryption capabilities

**Retention:** This project will remain publicly accessible for a minimum of five years (until at least 06/15/2030).

# Contact Information
Contact Name: Justin Anderson

Contact Email: justin.anderson@dot.gov

# Acknowledgements

## Citing this code
To track how this government-funded code is used, we request that if you decide to build additional software using this code please acknowledge it in your software's README/documentation.

To cite this code in a publication or report, please cite our associated report/paper and/or our source code. Below is a sample citation for this code:

_`ITS JPO`. (`2025`)._ `Misbehvaior Detection` _(`1.0`) [Source code]. Provided by ITS CodeHub through GitHub.com. Accessed YYYY-MM-DD from `https://github.com/usdot-jpo-codehub/Misbehavior-Detection/tree/main`._

When you copy or adapt from this code, please include the original URL you copied the source code from and date of retrieval as a comment in your code.
