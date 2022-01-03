/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PCI_DOE_COMMON_LIB_H__
#define __PCI_DOE_COMMON_LIB_H__

#include "industry_standard/pcidoe.h"
#include "industry_standard/pci_idekm.h"

/* definition following PCI DOE specification*/

#pragma pack(1)

typedef struct {
    spdm_message_header_t spdm_header;
    /* param1 == RSVD*/
    /* param2 == RSVD*/
    uint16_t standard_id; /* SPDM_STANDARD_ID_PCISIG*/
    uint8_t len;
    uint16_t vendor_id;  /* SPDM_VENDOR_ID_PCISIG*/
    uint16_t payload_length;
    pci_protocol_header_t pci_protocol;
} pci_doe_spdm_vendor_defined_request_t;

typedef struct {
    spdm_message_header_t spdm_header;
    /* param1 == RSVD*/
    /* param2 == RSVD*/
    uint16_t standard_id; /* SPDM_STANDARD_ID_PCISIG*/
    uint8_t len;
    uint16_t vendor_id;  /* SPDM_VENDOR_ID_PCISIG*/
    uint16_t payload_length;
    pci_protocol_header_t pci_protocol;
} pci_doe_spdm_vendor_defined_response_t;

#pragma pack()

/* PCI DOE - check below configuration*/
/* only Discovery*/
#define PCI_DOE_MAX_NON_SPDM_MESSAGE_SIZE 12
/* PCI DOE SPDM Vendor Defined - check below configuration*/
/* only IDE_KM*/
#define PCI_DOE_SPDM_VENDOR_MAX_MESSAGE_SIZE 0x100

/* defintion for library*/
typedef struct {
    uint16_t vendor_id;
    uint8_t  data_object_type;
} pci_doe_data_object_protocol_t;

#endif
