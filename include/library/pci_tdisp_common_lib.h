/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_COMMON_LIB_H
#define PCI_TDISP_COMMON_LIB_H

#include "industry_standard/pci_tdisp.h"

#define LIBTDISP_MAX_VERSION_COUNT 0x1
#define LIBTDISP_INTERFACE_REPORT_MAX_SIZE 0x1000

#define LIBTDISP_INTERFACE_REPORT_PORTION_LEN 0x40

#define LIBTDISP_ERROR_MESSAGE_MAX_SIZE (sizeof(pci_tdisp_error_response_t))

/*
 * Maximum size of a TDISP response message: the largest response is
 * GET_DEVICE_INTERFACE_REPORT, which carries up to
 * LIBTDISP_INTERFACE_REPORT_MAX_SIZE bytes of report data following the
 * report-response header.
 */
#define LIBTDISP_MAX_MESSAGE_SIZE \
    (sizeof(pci_tdisp_device_interface_report_response_t) + \
     LIBTDISP_INTERFACE_REPORT_MAX_SIZE)

#endif
