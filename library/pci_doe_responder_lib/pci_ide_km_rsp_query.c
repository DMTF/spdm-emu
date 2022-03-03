/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_responder_lib.h"

/**
    Process the IDE_KM request and return the response.

    @param request       the IDE_KM request message, start from pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the IDE_KM response message, start from pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_ide_km_get_response_query (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, uintn request_size,
    void *response, uintn *response_size)
{
    const pci_ide_km_query_t *ide_km_request;
    pci_ide_km_query_resp_t *ide_km_response;

    ide_km_request = request;
    ide_km_response = response;
    if (request_size != sizeof(pci_ide_km_query_t)) {
        return RETURN_INVALID_PARAMETER;
    }
    LIBSPDM_ASSERT (*response_size >= sizeof(pci_ide_km_query_resp_t));
    *response_size = sizeof(pci_ide_km_query_resp_t);

    libspdm_zero_mem (response, *response_size);
    ide_km_response->header.object_id = PCI_IDE_KM_OBJECT_ID_QUERY_RESP;

    /* TBD - need PCI context to get the info*/
    ide_km_response->port_index = ide_km_request->port_index;
    ide_km_response->dev_func_num = 0;
    ide_km_response->bus_num = 0;
    ide_km_response->segment = 0;
    ide_km_response->max_port_index = 7;

    return RETURN_SUCCESS;
}
