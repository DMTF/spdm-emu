/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
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
    const pci_doe_spdm_vendor_defined_request_large_t *spdm_request_large;
    pci_doe_spdm_vendor_defined_response_large_t *spdm_response_large;
    size_t index;
    size_t vendor_response_size;
    libspdm_return_t status;
    bool use_large_payload;
    size_t req_header_size;
    size_t req_payload_length;
    size_t rsp_header_size;
    size_t rsp_payload_length;
    const pci_protocol_header_t *req_pci_protocol;

    spdm_request = request;
    spdm_response = response;
    spdm_request_large = request;
    spdm_response_large = response;
    if (request_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    
    if ((spdm_request->spdm_header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((spdm_request->spdm_header.param1 & SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ) != 0)) {
        use_large_payload = true;
        req_header_size = sizeof(pci_doe_spdm_vendor_defined_request_large_t);
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_large_t);
    } else {
        use_large_payload = false;
        req_header_size = sizeof(pci_doe_spdm_vendor_defined_request_t);
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_t);
    }
    if (use_large_payload) {
        if (request_size < sizeof(pci_doe_spdm_vendor_defined_request_large_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        req_payload_length = spdm_request_large->pci_doe_vendor_header.payload_length;
        req_pci_protocol = &spdm_request_large->pci_doe_vendor_header.pci_protocol; 
    } else {
        if (request_size < sizeof(pci_doe_spdm_vendor_defined_request_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        req_payload_length = spdm_request->pci_doe_vendor_header.payload_length;
        req_pci_protocol = &spdm_request->pci_doe_vendor_header.pci_protocol; 
    }

    LIBSPDM_ASSERT (*response_size > req_header_size);
    vendor_response_size = *response_size - req_header_size;

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
    if (req_payload_length < sizeof(pci_protocol_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (req_payload_length - sizeof(pci_protocol_header_t) >
        request_size - req_header_size) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pci_doe_spdm_dispatch); index++) {
        if ((spdm_request->pci_doe_vendor_header.standard_id ==
             m_pci_doe_spdm_dispatch[index].standard_id) &&
            (spdm_request->pci_doe_vendor_header.vendor_id ==
             m_pci_doe_spdm_dispatch[index].vendor_id) &&
            (req_pci_protocol->protocol_id ==
             m_pci_doe_spdm_dispatch[index].protocol_id)) {
            status = m_pci_doe_spdm_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                (uint8_t *)request + req_header_size,
                req_payload_length - sizeof(pci_protocol_header_t),
                (uint8_t *)response + rsp_header_size,
                &vendor_response_size
                );
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
            rsp_payload_length = sizeof(pci_protocol_header_t) + vendor_response_size;

            libspdm_zero_mem (spdm_response, rsp_header_size);
            spdm_response->spdm_header.spdm_version = spdm_request->spdm_header.spdm_version;
            spdm_response->spdm_header.param1 = use_large_payload ?
                SPDM_VENDOR_DEFINED_RESPONSE_LARGE_RESP : 0;
            spdm_response->spdm_header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
            spdm_response->pci_doe_vendor_header.standard_id =
                spdm_request->pci_doe_vendor_header.standard_id;
            spdm_response->pci_doe_vendor_header.len =
                sizeof(spdm_response->pci_doe_vendor_header.vendor_id);
            spdm_response->pci_doe_vendor_header.vendor_id =
                spdm_request->pci_doe_vendor_header.vendor_id;
            if (use_large_payload) {
                spdm_response_large->pci_doe_vendor_header.payload_length =
                    (uint16_t)rsp_payload_length;
                spdm_response_large->pci_doe_vendor_header.pci_protocol.protocol_id =
                    req_pci_protocol->protocol_id;
            } else {
                spdm_response->pci_doe_vendor_header.payload_length =
                    (uint16_t)rsp_payload_length;
                spdm_response->pci_doe_vendor_header.pci_protocol.protocol_id =
                    req_pci_protocol->protocol_id;
            }

            *response_size = vendor_response_size + rsp_header_size;

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
