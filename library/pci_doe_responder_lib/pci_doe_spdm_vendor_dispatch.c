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
    pci_protocol_header_t                      header;
    pci_doe_get_spdm_vendor_response_func_t    func;
} pci_doe_spdm_dispatch_struct_t;

pci_doe_spdm_dispatch_struct_t m_pci_doe_spdm_dispatch[] = {
    {{PCI_PROTOCOL_ID_IDE_KM}, pci_ide_km_get_response},
};

/**
    Process the SPDM vendor defined request and return the response.

    @param request       the SPDM vendor defined request message, start from spdm_message_header_t.
    @param request_size  size in bytes of request.
    @param response      the SPDM vendor defined response message, start from spdm_message_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_doe_get_response_spdm_vendor_defined_request(IN void *pci_doe_context,
    IN void *spdm_context, IN uint32_t *session_id,
    IN void *request, IN uintn request_size,
    IN OUT void *response, IN OUT uintn *response_size)
{
    pci_doe_spdm_vendor_defined_request_t *spdm_request;
    pci_doe_spdm_vendor_defined_response_t *spdm_response;
    uintn index;
    uintn vendor_response_size;
    return_status status;

    spdm_request = request;
    spdm_response = response;
    if (request_size < sizeof(pci_doe_spdm_vendor_defined_request_t)) {
        return RETURN_INVALID_PARAMETER;
    }
    ASSERT (*response_size > sizeof(pci_doe_spdm_vendor_defined_response_t));
    vendor_response_size = *response_size - sizeof(pci_doe_spdm_vendor_defined_response_t);

    if (spdm_request->spdm_header.request_response_code != SPDM_VENDOR_DEFINED_REQUEST) {
        return RETURN_INVALID_PARAMETER;
    }
    if (spdm_request->standard_id != SPDM_REGISTRY_ID_PCISIG) {
        return RETURN_INVALID_PARAMETER;
    }
    if (spdm_request->len != sizeof(spdm_request->vendor_id)) {
        return RETURN_INVALID_PARAMETER;
    }
    if (spdm_request->vendor_id != SPDM_VENDOR_ID_PCISIG) {
        return RETURN_INVALID_PARAMETER;
    }
    if (spdm_request->payload_length < sizeof(pci_protocol_header_t)) {
        return RETURN_INVALID_PARAMETER;
    }
    if (spdm_request->payload_length - sizeof(pci_protocol_header_t) >
            request_size - sizeof(pci_doe_spdm_vendor_defined_request_t)) {
        return RETURN_INVALID_PARAMETER;
    }

    for (index = 0; index < ARRAY_SIZE(m_pci_doe_spdm_dispatch); index++) {
        if (spdm_request->pci_protocol.protocol_id == m_pci_doe_spdm_dispatch[index].header.protocol_id) {
            status = m_pci_doe_spdm_dispatch[index].func (
                        pci_doe_context, spdm_context, session_id,
                        (uint8_t *)request + sizeof(pci_doe_spdm_vendor_defined_request_t),
                        spdm_request->payload_length - sizeof(pci_protocol_header_t),
                        (uint8_t *)response + sizeof(pci_doe_spdm_vendor_defined_response_t),
                        &vendor_response_size
                        );
            if (RETURN_ERROR(status)) {
                return status;
            }

            zero_mem (spdm_response, sizeof(pci_doe_spdm_vendor_defined_response_t));
            spdm_response->spdm_header.spdm_version = spdm_request->spdm_header.spdm_version;
            spdm_response->spdm_header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
            spdm_response->standard_id = SPDM_REGISTRY_ID_PCISIG;
            spdm_response->len = sizeof(spdm_response->vendor_id);
            spdm_response->vendor_id = SPDM_VENDOR_ID_PCISIG;
            spdm_response->payload_length = (uint16_t)(sizeof(pci_protocol_header_t) + vendor_response_size);
            spdm_response->pci_protocol.protocol_id = spdm_request->pci_protocol.protocol_id;

            *response_size = vendor_response_size + sizeof(pci_doe_spdm_vendor_defined_response_t);

            return RETURN_SUCCESS;
        }
    }

    return RETURN_INVALID_PARAMETER;
}
