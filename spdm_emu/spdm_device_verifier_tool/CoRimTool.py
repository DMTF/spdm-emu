##
#
#  Copyright Notice:
#  Copyright 2021-2022 DMTF. All rights reserved.
#  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
#
# This tool generates CBOR format CoMID tag.
#
# Reference:
#   CoSWID: https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/
#   CORIM: https://datatracker.ietf.org/doc/draft-birkholz-rats-corim/
#
#   CBOR specifications, http://cbor.io/spec.html
#   CBOR, https://www.rfc-editor.org/rfc/rfc8949.html
#   COSE, https://datatracker.ietf.org/doc/html/rfc8152
#
#   Named Information, https://www.iana.org/assignments/named-information/named-information.xhtml
#
##

import os
import json
import cbor
import cbor2
import argparse

from cose.keys import EC2Key
from cose.messages.cosemessage import CoseMessage
from cose.messages.sign1message import Sign1Message
from ecdsa.keys import SigningKey, VerifyingKey

SupportHashAlgMap = {'sha256': 1, 'sha384': 7, 'sha512': 8}
SignSupportAlgorithmMap = {'ES256': -7, 'ES384': -35, 'ES512': -36}

CorimCborTags = {'corim': 500, 'unsigned_corim_map': 501, 'signed_corim': 502, 'consise_swid_tag': 505,
                 'consise_mid_tag': 506}
ComidCborTags = {'tagged_oid_type': 111, 'tagged_uuid_type': 37, 'tagged_ueid_type': 550, 'tagged_svn': 552,
                 'tagged_min_svn': 553}
CoseTypeMap = {'cose_sign': 98, 'cose_sign1': 18, 'cose_encrypt': 96, 'cose_encrypt0': 16, 'cose_mac': 97,
               'cose_mac0': 17}
ConciseMidTag = {'comid_language': 0, 'comid_tag_identity': 1, 'comid_entity': 2, 'comid_linked_tags': 3,
                 'comid_triples': 4}
TagIdentityMap = {'comid_tag_id': 0, 'comid_tag_version': 1}
EntityMap = {'comid_entity_name': 0, 'comid_reg_id': 1, 'comid_role': 2}
LinkedTagMap = {'comid_linked_tag_id': 0, 'comid_tag_rel': 1}
TriplesMap = {'comid_reference_triples': 0, 'comid_endorsed_triples': 1, 'comid_identity_triples': 2,
              'comid_attest_key_triples': 3}
EnvironmentMap = {'comid_class': 0, 'comid_instance': 1, 'comid_group': 2}
ClassMap = {'comid_class_id': 0, 'comid_vendor': 1, 'comid_model': 2, 'comid_layer': 3, 'comid_index': 4}
MeasurementMap = {'comid_mkey': 0, 'comid_mval': 1}
MeasurementValueMap = {'comid_ver': 0, 'comid_svn': 1, 'comid_digests': 2, 'comid_flags': 3, 'comid_raw_value': 4,
                       'comid_raw_value_mask': 5, 'comid_mac_addr': 6, 'comid_ip_addr': 7, 'comid_serial_number': 8,
                       'comid_ueid': 9, 'comid_uuid': 10, 'comid_name': 11}
VersionMap = {'comid_version': 0, 'comid_version_scheme': 1}
VerificationKeyMap = {'comid_key': 0, 'comid_keychain': 1}
TagRelTypeChoice = {'comid_supplements': 0, 'comid_replaces': 1}
ComidRoleTypeChoice = {'comid_tag_creator': 0, 'comid_creator': 1, 'comid_maintainer': 2}
UnsignedCorimMap = {'corim_id': 0, 'corim_tags': 1, 'corim_dependent_rims': 2, 'corim_profile': 3}
CorimLocatorMap = {'corim_href': 0, 'corim_thumbprint': 1}
ProtectedSignedCorimHeaderMap = {'corim_alg_id': 1, 'corim_content_type': 3, 'corim_issuer_key_id': 4, 'corim_meta': 8}
CorimMetaMap = {'corim_signer': 0, 'corim_validity': 1}
CorimEntityMap = {'corim_entity_name': 0, 'corim_reg_id': 1, 'corim_role': 2}
CorimRoleTypeChoice = {'corim_manifest_creator': 1, 'corim_manifest_signer': 2}
ValidityMap = {'corim_not_before': 0, 'corim_not_after': 1}

LogicMapList = {'unsigned_corim_map': UnsignedCorimMap, 'corim_dependent_rims': CorimLocatorMap,
                'corim_tags': ConciseMidTag, 'comid_tag_identity': TagIdentityMap, 'comid_entity': EntityMap,
                'comid_triples': TriplesMap, 'comid_role': ComidRoleTypeChoice, 'linked_tag_map': LinkedTagMap,
                'comid_reference_triples': EnvironmentMap, 'comid_endorsed_triples': EnvironmentMap,
                'comid_attest_key_triples': EnvironmentMap, 'comid_identity_triples': EnvironmentMap,
                'comid_class': ClassMap, 'comid_linked_tags': LinkedTagMap, 'comid_mval': MeasurementValueMap,
                'comid_digests': SupportHashAlgMap, 'cose_sign1': ProtectedSignedCorimHeaderMap,
                'corim_meta': CorimMetaMap, 'corim_signer': CorimEntityMap, 'corim_role': CorimRoleTypeChoice,
                'corim_alg_id': SignSupportAlgorithmMap, 'comid_ver': VersionMap}

AllMapDict = {**ConciseMidTag, **TagIdentityMap, **EntityMap, **LinkedTagMap, **TriplesMap, **EnvironmentMap,
              **ClassMap, **MeasurementMap, **MeasurementValueMap, **VersionMap, **VerificationKeyMap,
              **TagRelTypeChoice, **ComidRoleTypeChoice, **UnsignedCorimMap, **CorimLocatorMap,
              **ProtectedSignedCorimHeaderMap, **CorimMetaMap, **CorimEntityMap, **CorimRoleTypeChoice, **ValidityMap}

class JsonHandler:
    def __init__(self, file_path):
        self.FilePath = file_path

    def is_json(self):
        with open(self.FilePath, "r") as fp:
            try:
                json_data = json.loads(fp.read())
            except Exception:
                return False
            return True

    def parse_json(self):
        with open(self.FilePath, "r") as fp:
            json_data = json.loads(fp.read())
            return json_data

def GetKeyByValue(dict_list, value):
    for dict in dict_list:
        for key in dict.keys():
            if dict[key] == value:
                return key

def GenCbor(json_data, output):
    CborData = {}
    translate_data(CborData, json_data)
    # Add concise-swid-tag #6.505 or concise-mid-tag #6.506
    CborData[1] = cbor2.CBORTag(CorimCborTags['consise_mid_tag'], CborData[1])
    # Add corim tag #6.500 and unsigned-corim-map tag #6.501
    tagged_data = cbor2.CBORTag(CorimCborTags['corim'],
                                (cbor2.CBORTag(CorimCborTags['unsigned_corim_map'], CborData)))

    with open(output, 'wb') as f:
        f.write(cbor2.dumps(tagged_data))

    print(tagged_data)

def SignCbor(FilePath, Key, Algorithm, kid, SignedCborPath):
    with open(FilePath, 'rb') as f:
        cborData = f.read()

    with open(Key, 'rb') as f:
        private_key = SigningKey.from_pem(f.read()).to_string()

    #    COSE-Sign1-corim = [
    #      protected: bstr .cbor protected-corim-header-map
    #      unprotected: unprotected-corim-header-map
    #      payload: bstr .cbor tagged-corim-map
    #      signature: bstr
    #    ]
    protected_hdr_default = {
        "corim_alg_id": Algorithm,
        "corim_content_type": "application/rim+cbor",
        "corim_issuer_key_id": kid.encode(),
        "corim_meta": {
            "corim_signer": [
                {
                    "corim_entity_name": "Intel",
                    "corim_role": "corim_manifest_creator"
                }
            ]
        }
    }

    protected_hdr = {}
    translate_data(protected_hdr, protected_hdr_default)

    sign_msg = Sign1Message(phdr=protected_hdr, uhdr={}, payload=cborData, external_aad=b'')
    cose_key = EC2Key(crv='P_256', d=private_key)
    sign_msg.key = cose_key

    tagged_msg = cbor2.CBORTag(CorimCborTags['corim'],
                               cbor2.CBORTag(CorimCborTags['signed_corim'], cbor2.loads(sign_msg.encode())))
    with open(SignedCborPath, 'wb') as f:
        f.write(cbor2.dumps(tagged_msg))

    print(tagged_msg)

def translate_data(output, input):
    if isinstance(input, dict):
        for key in input.keys():
            if isinstance(input[key], dict):
                output[AllMapDict[key]] = {}
                translate_data(output[AllMapDict[key]], input[key])
            elif isinstance(input[key], list):
                output[AllMapDict[key]] = []
                translate_data(output[AllMapDict[key]], input[key])
            else:
                if key == "corim_role" and isinstance(input[key], str):
                    output[AllMapDict[key]] = AllMapDict[input[key]]
                elif key == "corim_alg_id" and isinstance(input[key], str):
                    output[AllMapDict[key]] = SignSupportAlgorithmMap[input[key]]
                else:
                    if "tagged" in key:
                        try:
                            tag_type = 'tagged' + key.split('tagged')[-1].strip()
                            actual_key = '_'.join(key.split('tagged')[0].strip().split('_')[0:-1])
                            output[AllMapDict[actual_key]] = cbor2.CBORTag(ComidCborTags[tag_type], input[key])
                        except Exception:
                            print("No '_' found in key as separator with tag")
                            exit()
                    else:
                        output[AllMapDict[key]] = input[key]
    elif isinstance(input, list):
        for index in range(len(input)):
            if isinstance(input[index], dict):
                output.append({})
                translate_data(output[index], input[index])
            elif isinstance(input[index], list):
                output.append([])
                translate_data(output[index], input[index])
            else:
                if input[index] == "comid_tag_creator":
                    output.append(AllMapDict[input[index]])
                elif input[index] == "sha256":
                    output.append(SupportHashAlgMap[input[index]])
                else:
                    output.append(input[index])

def VerifySignedCbor(FilePath, Key, Algorithm, Payload):
    try:
        with open(FilePath, 'rb') as f:
            cbor_data = cbor.load(f)
            cose_msg = CoseMessage.decode(cbor.dumps(cbor_data.value.value))

        with open(Key, 'rb') as f:
            key = VerifyingKey.from_pem(f.read()).to_string()

        cose_key = EC2Key(crv='P_256', d=key)
        cose_msg.key = cose_key

        cose_msg.verify_signature(Algorithm)
    except Exception:
        print("Signature verification failed")
        exit()

    with open(Payload, 'wb') as f:
        f.write(cbor_data.value.value.value[2])
    print("Signature verification passed")

class DecodeCbor():
    def __init__(self, file_path, json_path):
        self.FilePath = file_path
        self.JsonPath = json_path
        with open(self.FilePath, 'rb') as f:
            self.CborData = cbor.load(f)

    def Decoder(self, output, input, last_key):
        if isinstance(input, cbor.Tag):
            last_key = GetKeyByValue([CorimCborTags, CoseTypeMap], input.tag)
            if isinstance(input.value, dict) or isinstance(input.value, cbor.Tag):
                output[last_key] = {}
                self.Decoder(output[last_key], input.value, last_key)
            elif isinstance(input.value, list):
                output[last_key] = []
                self.Decoder(output[last_key], input.value, last_key)
        elif isinstance(input, dict):
            map_list = []
            if last_key in LogicMapList.keys():
                map_list = [LogicMapList[last_key]]
                # hard code need to fix (no comid_mkey in data)
                if last_key == 'comid_reference_triples':
                    if not MeasurementMap['comid_mkey'] in input.keys():
                        map_list = [MeasurementMap]
            for key in input.keys():
                last_key = GetKeyByValue(map_list, key)
                if isinstance(input[key], dict):
                    output[last_key] = {}
                    self.Decoder(output[last_key], input[key], last_key)
                elif isinstance(input[key], list):
                    output[last_key] = []
                    self.Decoder(output[last_key], input[key], last_key)
                elif isinstance(input[key], cbor.Tag):
                    # hardcode need to fix
                    if input[key].tag == CorimCborTags['consise_mid_tag']:
                        output[last_key] = []
                        self.Decoder(output[last_key], input[key].value, last_key)
                    elif input[key].tag in ComidCborTags.values():
                        output[last_key + '_' + GetKeyByValue([ComidCborTags], input[key].tag)] = input[key].value
                else:
                    if last_key in ['corim_role', 'corim_alg_id']:
                        output[last_key] = GetKeyByValue([LogicMapList[last_key]], input[key])
                    else:
                        if isinstance(input[key], bytes):
                            output[last_key] = input[key].decode()
                        else:
                            output[last_key] = input[key]
        elif isinstance(input, list):
            for index in range(len(input)):
                if isinstance(input[index], dict):
                    output.append({})
                    self.Decoder(output[index], input[index], last_key)
                elif isinstance(input[index], list):
                    output.append([])
                    self.Decoder(output[index], input[index], last_key)
                else:
                    map_list = []
                    if last_key in ['comid_role', 'comid_digests', 'corim_role']:
                        map_list = [LogicMapList[last_key]]
                    if map_list:
                        value = GetKeyByValue(map_list, input[index])
                        if value == None:
                            output.append(input[index])
                        else:
                            output.append(value)
                    elif last_key == 'cose_sign1':
                        if index != 3:
                            output.append({})
                            if input[index] != {}:
                                self.Decoder(output[index], cbor.loads(input[index]), last_key)
                        else:
                            output.append(str(input[index]))
                    else:
                        if isinstance(input[index], bytes):
                            output.append(input[index].decode())
                        else:
                            output.append(input[index])

    def Decode(self):
        json_dict = {}
        self.Decoder(json_dict, self.CborData, '')
        with open(self.JsonPath, 'wb') as f:
            f.write(json.dumps(json_dict, indent=2).encode())
        print(json.dumps(json_dict, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest='which')

    parser_json_to_cbor = subparsers.add_parser('json_to_cbor', help='Generate CoRIM file in CBOR format')
    parser_json_to_cbor.set_defaults(which='json_to_cbor')
    parser_json_to_cbor.add_argument('-i', dest='ManifestPath', type=str, help='Corim manifest json file path',
                                     required=True)
    parser_json_to_cbor.add_argument('-o', dest='OutputFile', type=str, help='Output Cbor file path', default='',
                                     required=True)

    parser_cbor_to_json = subparsers.add_parser('cbor_to_json', help='Translate cbor to json')
    parser_cbor_to_json.set_defaults(which='cbor_to_json')
    parser_cbor_to_json.add_argument('-i', dest='CborFile', type=str, help='Cbor format file path', required=True)
    parser_cbor_to_json.add_argument('-o', dest='CorimJson', type=str, help='Corim json file', required=True)

    parser_sign = subparsers.add_parser('sign', help='Sign CoRIM CBOR file')
    parser_sign.set_defaults(which='sign')
    parser_sign.add_argument('-f', dest='File', type=str, help='unsigned reference file', required=True)
    parser_sign.add_argument('--key', dest='PrivateKey', type=str, help='PEM private key file', required=True)
    parser_sign.add_argument('--kid', dest='kid', type=str, help='User input KID', required=True)
    parser_sign.add_argument('--alg', dest='Algorithm', type=str, choices=SignSupportAlgorithmMap.keys(),
                             help='Signing algorithm', required=True)
    parser_sign.add_argument('-o', dest='SignedCborPath', type=str, help='SignedCbor file path COSE',
                             required=True)

    parser_verify = subparsers.add_parser('verify', help='Verify signature of signed COSE file and extract payload')
    parser_verify.set_defaults(which='verify')
    parser_verify.add_argument('-f', dest='File', type=str, help='Signed file path', required=True)
    parser_verify.add_argument('--key', dest='PublicKey', type=str, help='PEM public key file', required=True)
    parser_verify.add_argument('--alg', dest='Algorithm', type=str, choices=SignSupportAlgorithmMap.keys(),
                               help='Signing algorithm', required=True)
    parser_verify.add_argument('-o', dest='Payload', type=str, help='unsigned reference file', required=True)

    args = parser.parse_args()

    if args.which == 'json_to_cbor':
        if not os.path.exists(args.ManifestPath):
            raise Exception("ERROR: Could not locate manifest json file '%s' !" % args.ManifestPath)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

    if args.which == 'sign':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate Cbor file '%s' !" % args.File)
        if not os.path.exists(args.PrivateKey):
            raise Exception("ERROR: Could not locate PEM private key file '%s' !" % args.PrivateKey)
        if os.path.isabs(args.SignedCborPath):
            if not os.path.exists(os.path.dirname(args.SignedCborPath)):
                os.makedirs(os.path.dirname(args.SignedCborPath))

    if args.which == 'verify':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate file '%s' !" % args.File)
        if not os.path.exists(args.PublicKey):
            raise Exception("ERROR: Could not locate PEM private key file '%s' !" % args.PublicKey)
        if os.path.isabs(args.Payload):
            if not os.path.exists(os.path.dirname(args.Payload)):
                os.makedirs(os.path.dirname(args.Payload))

    if args.which == 'cbor_to_json':
        if not os.path.exists(args.CborFile):
            raise Exception("ERROR: Could not locate manifest json file '%s' !" % args.CborFile)
        if os.path.isabs(args.CorimJson):
            if not os.path.exists(os.path.dirname(args.CorimJson)):
                os.makedirs(os.path.dirname(args.CorimJson))

    if args.which == 'json_to_cbor':
        json_obj = JsonHandler(args.ManifestPath)
        if json_obj.is_json():
            data = json_obj.parse_json()
        else:
            raise Exception("ERROR: manifest json file '%s' is not json format !" % args.ManifestPath)

        GenCbor(data, args.OutputFile)

    if args.which == 'sign':
        SignCbor(args.File, args.PrivateKey, args.Algorithm, args.kid, args.SignedCborPath)

    if args.which == 'verify':
        VerifySignedCbor(args.File, args.PublicKey, args.Algorithm, args.Payload)

    if args.which == 'cbor_to_json':
        Decode = DecodeCbor(args.CborFile, args.CorimJson)
        Decode.Decode()
