/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_validator_sample.h"

void *m_pci_doe_context;
#define DOE_DISCOVERY_VERSION 0

libspdm_return_t pci_doe_init_request()
{
    pci_doe_data_object_protocol_t data_object_protocol[6];
    size_t data_object_protocol_size;
    libspdm_return_t status;
    uint32_t index;

    data_object_protocol_size = sizeof(data_object_protocol);
    status =
        pci_doe_discovery (m_pci_doe_context, data_object_protocol, &data_object_protocol_size, DOE_DISCOVERY_VERSION);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (index = 0; index < data_object_protocol_size/sizeof(pci_doe_data_object_protocol_t);
         index++) {
        printf("DOE(0x%x) VendorId-0x%04x, DataObjectType-0x%02x\n",
               index, data_object_protocol[index].vendor_id,
               data_object_protocol[index].data_object_type);
    }

    return LIBSPDM_STATUS_SUCCESS;
}
