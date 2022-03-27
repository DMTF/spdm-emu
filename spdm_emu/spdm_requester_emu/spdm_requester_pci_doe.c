/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

void *m_pci_doe_context;

libspdm_return_t pci_doe_init_request()
{
    pci_doe_data_object_protocol_t data_object_protocol[6];
    size_t data_object_protocol_size;
    libspdm_return_t status;
    uint32_t index;

    data_object_protocol_size = sizeof(data_object_protocol);
    status =
        pci_doe_discovery (m_pci_doe_context, data_object_protocol, &data_object_protocol_size);
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

libspdm_return_t pci_doe_process_session_message(void *spdm_context, uint32_t session_id)
{
    uint8_t max_port_index;
    libspdm_return_t status;
    uint8_t index;
    uint8_t temp_max_port_index;

    status = pci_ide_km_query (m_pci_doe_context, spdm_context, &session_id, 0, &max_port_index);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (index = 1; index <= max_port_index; index++) {
        status = pci_ide_km_query (m_pci_doe_context, spdm_context, &session_id, index,
                                   &temp_max_port_index);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }
    return LIBSPDM_STATUS_SUCCESS;
}
