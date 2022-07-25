##
#
#  Copyright 2021-2022 DMTF. All rights reserved.
#  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
#
# This tool generates evidence json file by parsing measurement binary.
#
##

import os
import json
import argparse
from copy import deepcopy
from ctypes import *

BIT0 = 1
BIT1 = 2
BIT2 = 4
BIT3 = 8
BIT4 = 16
BIT5 = 32
BIT6 = 64
BIT7 = 128

SupportHashAlgMap = {'sha256': 1, 'sha384': 7, 'sha512': 8}


class MEASUREMENT_SPEC_HDR(Structure):
    _fields_ = [
        ('measurement_value_type', c_uint8),
        ('measurement_value_size', c_uint16)
    ]


class MEASUREMENT_BLK(Structure):
    _fields_ = [
        ('index', c_uint8),
        ('measurement_specification', c_uint8),
        ('measurement_size', c_uint16),
        ('measurement', MEASUREMENT_SPEC_HDR)
    ]


class ParseMeasurement:
    def __init__(self, measurement_file, alg, output_json):
        fp = open(measurement_file, 'rb')
        self.bin_data = bytearray(fp.read())
        fp.close()

        self.alg = alg
        self.output = output_json
        self.evidences = {'evidences': []}
        self.evidence_type1 = {'evidence': {'index': 0, 'digest': [0, 0]}}
        self.evidence_type2 = {'evidence': {'index': 0, 'svn': ''}}

    def append_evidence(self, evidence):
        self.evidences['evidences'].append(evidence)

    def parse(self):
        offset = 0

        while (offset < len(self.bin_data)):
            measurement = MEASUREMENT_BLK.from_buffer(self.bin_data, offset)
            if measurement.measurement.measurement_value_type & BIT7 == 0:
                evidence = deepcopy(self.evidence_type1)
                evidence['evidence']['index'] = measurement.index
                evidence['evidence']['digest'][0] = SupportHashAlgMap[self.alg]
                evidence['evidence']['digest'][1] = \
                    bytearray.hex(self.bin_data[offset + 3 * sizeof(c_uint8) + 2 * sizeof(c_uint16): offset + \
                                    2 * sizeof(c_uint8) + sizeof(c_uint16) + measurement.measurement_size])
                self.append_evidence(evidence)
            else:
                if measurement.measurement.measurement_value_type ^ BIT7 == 7:
                    evidence = deepcopy(self.evidence_type2)
                    evidence['evidence']['index'] = measurement.index
                    evidence['evidence']['svn'] = c_uint64.from_buffer(self.bin_data, offset + 3 * sizeof(c_uint8) + 2 * sizeof(c_uint16)).value
                    self.append_evidence(evidence)

            offset += 2 * sizeof(c_uint8) + sizeof(c_uint16) + measurement.measurement_size

        with open(self.output, 'wb') as f:
            f.write(json.dumps(self.evidences, indent=2).encode())

        print("{}".format(json.dumps(self.evidences, indent=2)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest='which')

    parser_meas_to_json = subparsers.add_parser('meas_to_json', help='Parse measurement binary and generate json format file')
    parser_meas_to_json.set_defaults(which='meas_to_json')
    parser_meas_to_json.add_argument('--meas', dest='MeasurementBin', type=str, help='Measurement binary file path', required=True)
    parser_meas_to_json.add_argument('--alg', dest='HashAlg', type=str, help='Hash algorithm', choices=SupportHashAlgMap.keys(), required=True)
    parser_meas_to_json.add_argument('-o', dest='OutputFile', type=str, help='Output json file path', default='', required=True)

    args = parser.parse_args()

    if args.which == 'json_to_cbor':
        if not os.path.exists(args.MeasurementBin):
            raise Exception("ERROR: Could not measurement binary file '%s' !" % args.MeasurementBin)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

    pa = ParseMeasurement(args.MeasurementBin, args.HashAlg, args.OutputFile)
    pa.parse()