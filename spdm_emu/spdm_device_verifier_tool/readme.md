# This SPDM manifest tool is a sample implementation.

## Specification

   * CoRIM / CoMID:
     * RATS: [Concise Reference Integrity Manifest](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/)

   * CoSWID:
     * RATS: [Remote Attestation Procedures Architecture](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/)
     * SACM: [Concise Software Identification Tags](https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/)
     * RATS: [Reference Integrity Measurement Extension for Concise Software Identities](https://datatracker.ietf.org/doc/draft-birkholz-rats-coswid-rim/)

   * [CBOR](http://cbor.io/):
     * CBOR: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)
     * COSE: [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152)
     * IANA: [Named Information](https://www.iana.org/assignments/named-information/named-information.xhtml)

   * Other standard: TCG DICE
     * TCG: [DICE Endorsement Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Endorsement-Architecture-for-Devices-r38_5May22.pdf)
     * TCG: [DICE Attestation Architecture](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/)
     * TCG: [DICE Layering Architecture](https://trustedcomputinggroup.org/resource/dice-layering-architecture/)
     * TCG: [DICE certificate Profile](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/)
     * TCG: [DICE Symmetric Identity Based Device Attestation](https://trustedcomputinggroup.org/resource/symmetric-identity-based-device-attestation/)

## Feature

The tools can generate CoRIM(CoSWID/CoMID) for SPDM measurement.

The tools can also verify the CoRIM(CoSWID/CoMID) based upon SPDM measurement runtime collection.

## RIM Generation

### prerequisites

 * Install required python package:

   `pip install -r requirements.txt`

 * Prepare KEY files (private and public).

   The sample test KEY are at [SampleTestKey](SampleTestKey). Please do NOT use them in any production.

### Prepare reference file

   The reference file is JSON format. It can be converted to CBOR format by `CoRimTool.py`.

### Generate RIM

#### Use CoRIM (CoSWID or CoMID) tool

   ```
   CoRimTool.py json_to_cbor -i <json file> -o <cbor file>
   CoRimTool.py cbor_to_json -i <cbor file> -o <json file>
   CoRimTool.py sign -f <unsigned reference file> --key <PEM private key file> --kid <User input KID> --alg <signing algo - ES256|ES384|ES512> -o <signed reference file>
   CoRimTool.py verify -f <signed reference file> --key <PEM public key file> --alg <signing algo - ES256|ES384|ES512> -o <unsigned reference file>
   ```

   The signed or unsigned reference file is CBOR format. With cbor_to_json, it can be converted to JSON format.

   * CBOR/JSON translation

   We use the key name in [CoRIM](https://datatracker.ietf.org/doc/draft-birkholz-rats-corim/) and [CoSWID](https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/) CDDL definition. The separators such as "." or "-" are converted to "_". This is to meet [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) variable name requirement.

   For example, "corim.alg-id" is encoded as 1 in CBOR format. Then the JSON file will use "corim_alg_id" as the key name.

   * CBOR tag support

   CBOR supports tagged data. In order to translate tagged data between CBOR and JSON, we append tagged string to the key name with "_" as separator.

   For example, "comid.svn" can use a tag to indicate "tagged-svn" #6.552(svn) or "tagged-min-svn" #6.553(min-svn). Then the JSON key name will be "comid_svn_tagged_svn" or "comid_svn_tagged_min_svn".

## Verification

### Prepare evidence file

#### Prepare SPDM measurement evidence

   `SpdmMeasurement.py meas_to_json --meas <measurement binary file> --alg <hash algo - sha256|sha384|sha512> -o <evidence file>` 

   Evidence file is JSON format.

### Verify Evidence

#### Use [OPA](https://www.openpolicyagent.org/)
   
   Refer to [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policy.

   * Generate OPA input file
   
   `OpaTool.py -e <evidence file> -r <reference file> -o <OPA input file>`.

   Evidence file is JSON format. Reference file is JSON format.
   The final OPA input file adds "evidence" and "reference" key for the evidence file and reference file.

   * Defile policy

   Put spdm policy rego file to left window

   * Evaluate on "The Rego Playground" portal

   Evaluate hash in SPDM measurement binary with hash in SPDM device RIM on "The Rego Playground" portal:

   ```
   Open https://play.openpolicyagent.org/
   Copy content in <policy file> to left window.
   Copy content in <OPA input file> to 'Input' window
   Click 'Evaluate' button, then check result in 'Output' window
   ```

   * Evaluate with OPA command line tool 

   Download OPA - https://www.openpolicyagent.org/docs/latest/#1-download-opa.
   
   Evaluate Policy - https://www.openpolicyagent.org/docs/latest/#2-try-opa-eval.

   Run: `opa eval -i <OPA input file> -d <policy> "<query>"`

   For example: `opa eval -i <OPA input file> -d <spdm policy rego file> "data.spdm"`

## Example Flow with SPDM device CoRIM

## Publish

   ```
   // Create reference measurement json file.
   CoRimTool.py json_to_cbor -i SampleManifests/SpdmSampleCoMid.json -o SampleManifests/SpdmSampleCoMid.cbor
   CoRimTool.py sign -f SampleManifests/SpdmSampleCoMid.cbor --key SampleTestKey/ecc-private-key.pem --kid 11 --alg ES256 -o SampleManifests/SpdmSampleCoMid.corim
   ```

   Publish signed reference cbor file.

## Verification

   Collect SPDM measurement binary file.

   ```
   CoRimTool.py verify -f SampleManifests/SpdmSampleCoMid.corim --key SampleTestKey/ecc-public-key.pem --alg ES256 -o SampleManifests/SpdmSampleCoMid.corim.cbor
   CoRimTool.py cbor_to_json -i SampleManifests/SpdmSampleCoMid.corim.cbor -o SampleManifests/SpdmSampleCoMid.corim.json
   // Collect Measurment Binary, e.g. run spdm_device_attester_sample, and get device_measurement.bin.
   SpdmMeasurement.py meas_to_json --meas SampleEvidence/device_measurement.bin --alg sha512 -o SampleEvidence/SpdmSampleMeasurement.json
   OpaTool.py -e SampleEvidence/SpdmSampleMeasurement.json -r SampleManifests/SpdmSampleCoMid.corim.json -o opa.input
   opa eval -i opa.input -d SpdmSamplePolicy.rego "data.spdm"
   ```
