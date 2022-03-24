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

typedef struct {
    pci_ide_km_header_t               header;
    pci_ide_km_get_response_func_t    func;
} pci_doe_spdm_dispatch_struct_t;

pci_doe_spdm_dispatch_struct_t m_pci_idm_km_dispatch[] = {
    {{PCI_IDE_KM_OBJECT_ID_QUERY}, pci_ide_km_get_response_query}, 
};

/**
    Process the IDE_KM request and return the response.

    @param request       the IDE_KM request message, start from pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the IDE_KM response message, start from pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_ide_km_get_response (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    const pci_ide_km_header_t *ide_km_request;
    size_t index;

    ide_km_request = request;
    if (request_size < sizeof(pci_ide_km_header_t)) {
        return RETURN_INVALID_PARAMETER;
    }

    for (index = 0; index < ARRAY_SIZE(m_pci_idm_km_dispatch); index++) {
        if (ide_km_request->object_id == m_pci_idm_km_dispatch[index].header.object_id) {
            return m_pci_idm_km_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                request, request_size, response, response_size);
        }
    }

    return RETURN_INVALID_PARAMETER;
}
