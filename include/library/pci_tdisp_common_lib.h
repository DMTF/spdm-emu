/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_COMMON_LIB_H
#define PCI_TDISP_COMMON_LIB_H

#include "industry_standard/pci_tdisp.h"

#define LIBTDISP_MAX_VERSION_COUNT 0x1
#define LIBTDISP_INTERFACE_REPORT_MAX_SIZE 0x1000

#define LIBTDISP_INTERFACE_REPORT_PORTION_LEN 0x40

#define LIBTDISP_ERROR_MESSAGE_MAX_SIZE (sizeof(pci_tdisp_error_response_t))

#endif
