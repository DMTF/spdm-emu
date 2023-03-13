/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_responder_lib.h"

typedef struct {
    uint16_t standard_id;
    uint16_t vendor_id;
    uint8_t protocol_id;
    pci_doe_get_spdm_vendor_response_func_t func;
} pci_doe_spdm_dispatch_struct_t;

pci_doe_spdm_dispatch_struct_t m_pci_doe_spdm_dispatch[4];
size_t m_pci_doe_spdm_dispatch_count;

/**
 *  Process the SPDM vendor defined request and return the response.
 *
 *  @param request       the SPDM vendor defined request message, start from spdm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the SPDM vendor defined response message, start from spdm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pci_doe_get_response_spdm_vendor_defined_request(const void *pci_doe_context,
                                                                  void *spdm_context,
                                                                  const uint32_t *session_id,
                                                                  const void *request,
                                                                  size_t request_size,
                                                                  void *response,
                                                                  size_t *response_size)
{
    const pci_doe_spdm_vendor_defined_request_t *spdm_request;
    pci_doe_spdm_vendor_defined_response_t *spdm_response;
    size_t index;
    size_t vendor_response_size;
    libspdm_return_t status;

    spdm_request = request;
    spdm_response = response;
    if (request_size < sizeof(pci_doe_spdm_vendor_defined_request_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size > sizeof(pci_doe_spdm_vendor_defined_response_t));
    vendor_response_size = *response_size - sizeof(pci_doe_spdm_vendor_defined_response_t);

    if (spdm_request->spdm_header.request_response_code != SPDM_VENDOR_DEFINED_REQUEST) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->pci_doe_vendor_header.standard_id != SPDM_REGISTRY_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->pci_doe_vendor_header.len !=
        sizeof(spdm_request->pci_doe_vendor_header.vendor_id)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->pci_doe_vendor_header.payload_length < sizeof(pci_protocol_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->pci_doe_vendor_header.payload_length - sizeof(pci_protocol_header_t) >
        request_size - sizeof(pci_doe_spdm_vendor_defined_request_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pci_doe_spdm_dispatch); index++) {
        if ((spdm_request->pci_doe_vendor_header.standard_id ==
             m_pci_doe_spdm_dispatch[index].standard_id) &&
            (spdm_request->pci_doe_vendor_header.vendor_id ==
             m_pci_doe_spdm_dispatch[index].vendor_id) &&
            (spdm_request->pci_doe_vendor_header.pci_protocol.protocol_id ==
             m_pci_doe_spdm_dispatch[index].protocol_id)) {
            status = m_pci_doe_spdm_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                (uint8_t *)request + sizeof(pci_doe_spdm_vendor_defined_request_t),
                spdm_request->pci_doe_vendor_header.payload_length - sizeof(pci_protocol_header_t),
                (uint8_t *)response + sizeof(pci_doe_spdm_vendor_defined_response_t),
                &vendor_response_size
                );
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }

            libspdm_zero_mem (spdm_response, sizeof(pci_doe_spdm_vendor_defined_response_t));
            spdm_response->spdm_header.spdm_version = spdm_request->spdm_header.spdm_version;
            spdm_response->spdm_header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
            spdm_response->pci_doe_vendor_header.standard_id =
                spdm_request->pci_doe_vendor_header.standard_id;
            spdm_response->pci_doe_vendor_header.len =
                sizeof(spdm_response->pci_doe_vendor_header.vendor_id);
            spdm_response->pci_doe_vendor_header.vendor_id =
                spdm_request->pci_doe_vendor_header.vendor_id;
            spdm_response->pci_doe_vendor_header.payload_length =
                (uint16_t)(sizeof(pci_protocol_header_t) + vendor_response_size);
            spdm_response->pci_doe_vendor_header.pci_protocol.protocol_id =
                spdm_request->pci_doe_vendor_header.pci_protocol.protocol_id;

            *response_size = vendor_response_size + sizeof(pci_doe_spdm_vendor_defined_response_t);

            return LIBSPDM_STATUS_SUCCESS;
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

/**
 *  Register vendor response function.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pci_doe_register_vendor_response_func (const void *pci_doe_context,
                                                        uint16_t standard_id,
                                                        uint16_t vendor_id,
                                                        uint8_t protocol_id,
                                                        pci_doe_get_spdm_vendor_response_func_t func
                                                        )
{
    if (standard_id != SPDM_REGISTRY_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    LIBSPDM_ASSERT (m_pci_doe_spdm_dispatch_count < LIBSPDM_ARRAY_SIZE(m_pci_doe_spdm_dispatch));
    if (m_pci_doe_spdm_dispatch_count >= LIBSPDM_ARRAY_SIZE(m_pci_doe_spdm_dispatch)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    m_pci_doe_spdm_dispatch[m_pci_doe_spdm_dispatch_count].standard_id = standard_id;
    m_pci_doe_spdm_dispatch[m_pci_doe_spdm_dispatch_count].vendor_id = vendor_id;
    m_pci_doe_spdm_dispatch[m_pci_doe_spdm_dispatch_count].protocol_id = protocol_id;
    m_pci_doe_spdm_dispatch[m_pci_doe_spdm_dispatch_count].func = func;

    m_pci_doe_spdm_dispatch_count++;

    return LIBSPDM_STATUS_SUCCESS;
}
