# rust-sgx-remote-attestation
Remote attestation framework for Fortanix EDP
## Disclaimer
This project is highly experimental at the current stage, so please do not attemp to use it in production. I will keep updating the code and adding more instructions soon.
## How to Build and Run
1. Sign up for an account at https://api.portal.trustedservices.intel.com/EPID-attestation and make sure that the Name Base Mode is Linkable Quote (this is all the SDK can support for now). Take note of "SPID", "Primary key", and "Secondary key".
2. Modify the following fields in [settings.json](sample-sp/data/settings.json) using the information from the previous step:
  - "spid": "\<SPID\>"
  - "primary_subscription_key": "\<Primary Key\>"
  - "secondary_subscription_key": "\<Secondary key\>"
3. Download IAS's root certificate from [this link](https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem) and save the cerficate file in directory [sample-sp/data](sample-sp/data). Make sure the file name is "Intel_SGX_Attestation_RootCA.pem".
4. Run the script `build.sh` and `run.sh` consecutively from the main directory.

If there are no error messages on the screen, then the remote attestation has run successfully.
