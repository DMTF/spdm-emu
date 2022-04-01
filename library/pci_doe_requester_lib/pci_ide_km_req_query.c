/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_requester_lib.h"

libspdm_return_t pci_ide_km_query(const void *pci_doe_context,
                               void *spdm_context, const uint32_t *session_id,
                               uint8_t port_index, uint8_t *max_port_index)
{
    libspdm_return_t status;
    pci_ide_km_query_t request;
    size_t request_size;
    pci_ide_km_query_resp_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.object_id = PCI_IDE_KM_OBJECT_ID_QUERY;
    request.port_index = port_index;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = ide_km_send_receive_data(spdm_context, session_id,
                                      &request, request_size,
                                      &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(pci_ide_km_query_resp_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response.header.object_id != PCI_IDE_KM_OBJECT_ID_QUERY_RESP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.port_index != request.port_index) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    *max_port_index= response.max_port_index;

    return LIBSPDM_STATUS_SUCCESS;
}
