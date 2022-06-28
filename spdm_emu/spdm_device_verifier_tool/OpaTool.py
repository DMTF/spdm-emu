##
#
#  Copyright Notice:
#  Copyright 2021-2022 DMTF. All rights reserved.
#  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
#
# This tool generates OPA input file from evidence file and reference file.
#
##

import os
import json
import argparse

def is_json(file):
    with open(file, "r") as fp:
        try:
            json_data = json.loads(fp.read())
        except Exception:
            return False
        return True

def gen_opa_input(evidence_path, reference_path, opa):
    opa_temp = {
        "evidence": "",
        "reference": ""
    }
    with open(evidence_path, 'r') as fp:
        evidence_data = json.loads(fp.read())
        opa_temp["evidence"] = evidence_data

    with open(reference_path, 'r') as fp:
        reference_data = json.loads(fp.read())
        opa_temp["reference"] = reference_data

    with open(opa, 'w') as fp:
        fp.write(json.dumps(opa_temp, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-e', dest='Evidence', type=str, help='Json evidence file path', required=True)
    parser.add_argument('-r', dest='Reference', type=str, help='Json reference file path', required=True)
    parser.add_argument('-o', dest='Opa', type=str, help='Json OPA file path', required=True)

    args = parser.parse_args()

    if not os.path.exists(args.Evidence):
        raise Exception("ERROR: Could not locate json Evidence file '%s' !" % args.Evidence)
    if not is_json(args.Evidence):
        raise Exception("ERROR: '%s' is not a json format file and cannot be parse !" % args.Evidence)
    if not os.path.exists(args.Reference):
        raise Exception("ERROR: Could not locate json Reference file '%s' !" % args.Reference)
    if not is_json(args.Reference):
        raise Exception("ERROR: '%s' is not a json format file and cannot be parse !" % args.Reference)

    gen_opa_input(args.Evidence, args.Reference, args.Opa)
