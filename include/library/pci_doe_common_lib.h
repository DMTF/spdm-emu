/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __PCI_DOE_COMMON_LIB_H__
#define __PCI_DOE_COMMON_LIB_H__

#include "industry_standard/pcidoe.h"

/* PCI DOE - check below configuration
 * only Discovery*/
#define LIBPCIDOE_MAX_NON_SPDM_MESSAGE_SIZE 12
/* PCI DOE SPDM Vendor Defined - check below configuration
 * only IDE_KM*/
#define LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE 0x400

/* defintion for library*/
typedef struct {
    uint16_t vendor_id;
    uint8_t data_object_type;
} pci_doe_data_object_protocol_t;

#endif
