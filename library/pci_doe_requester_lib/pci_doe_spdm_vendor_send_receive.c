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
#include "library/pci_doe_requester_lib.h"

/**
 * Send and receive an SPDM vendor defined message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the SPDM vendor defined request message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the SPDM vendor defined response message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The SPDM vendor defined request is sent and response is received.
 * @return ERROR                        The SPDM vendor defined response is not received correctly.
 **/
libspdm_return_t pci_doe_spdm_vendor_send_receive_data_ex (
    void *spdm_context, const uint32_t *session_id,
    uint16_t vendor_id,
    pci_protocol_header_t pci_protocol,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;
    uint32_t req_cap;
    uint32_t rsp_cap;
    size_t data_size;
    libspdm_return_t status;
    uint8_t request_buffer[sizeof(pci_doe_spdm_vendor_defined_request_large_t) +
                           LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE];
    pci_doe_spdm_vendor_defined_request_t *spdm_request;
    pci_doe_spdm_vendor_defined_request_large_t *spdm_request_large;
    size_t spdm_request_size;
    uint8_t response_buffer[sizeof(pci_doe_spdm_vendor_defined_response_large_t) +
                            LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE];
    pci_doe_spdm_vendor_defined_response_t *spdm_response;
    pci_doe_spdm_vendor_defined_response_large_t *spdm_response_large;
    size_t spdm_response_size;
    bool use_large_payload;
    size_t req_header_size;
    size_t req_payload_length;
    size_t rsp_header_size;
    size_t rsp_payload_length;
    pci_protocol_header_t *rsp_pci_protocol;

    spdm_request = (void *)request_buffer;
    spdm_response = (void *)response_buffer;
    spdm_request_large = (void *)request_buffer;
    spdm_response_large = (void *)response_buffer;
    LIBSPDM_ASSERT (request_size <= LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE);
    LIBSPDM_ASSERT (*response_size < LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&spdm_version, sizeof(spdm_version));
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version, &data_size);
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_size = sizeof(req_cap);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &req_cap, &data_size);
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(rsp_cap);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &rsp_cap, &data_size);
    if ((spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((req_cap & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP) != 0) &&
        ((rsp_cap & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP) != 0)) {
        use_large_payload = true;
        req_header_size = sizeof(pci_doe_spdm_vendor_defined_request_large_t);
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_large_t);
    } else {
        use_large_payload = false;
        req_header_size = sizeof(pci_doe_spdm_vendor_defined_request_t);
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_t);
    }

    libspdm_zero_mem(spdm_request, req_header_size);
    spdm_request->spdm_header.spdm_version =
        (uint8_t)(spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);
    spdm_request->spdm_header.param1 = use_large_payload ?
        SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ : 0;
    spdm_request->spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request->pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_PCISIG;
    spdm_request->pci_doe_vendor_header.len = sizeof(spdm_request->pci_doe_vendor_header.vendor_id);
    spdm_request->pci_doe_vendor_header.vendor_id = vendor_id;
    req_payload_length = sizeof(pci_protocol_header_t) + request_size;
    if (use_large_payload) {
        spdm_request_large->pci_doe_vendor_header.payload_length =
            (uint16_t)req_payload_length;
        spdm_request_large->pci_doe_vendor_header.pci_protocol = pci_protocol;
    } else {
        spdm_request->pci_doe_vendor_header.payload_length =
            (uint16_t)req_payload_length;
        spdm_request->pci_doe_vendor_header.pci_protocol = pci_protocol;
    }
    libspdm_copy_mem((uint8_t *)spdm_request + req_header_size, request_size, request, request_size);

    spdm_request_size = req_header_size + request_size;
    spdm_response_size = rsp_header_size + (*response_size);
    status = libspdm_send_receive_data(spdm_context, session_id,
                                       false, spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    /* clear the copied memory, because it may include secret */
    libspdm_zero_mem ((uint8_t *)spdm_request + req_header_size, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->spdm_header.spdm_version != spdm_request->spdm_header.spdm_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if ((spdm_response->spdm_header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((spdm_response->spdm_header.param1 & SPDM_VENDOR_DEFINED_RESPONSE_LARGE_RESP) != 0)) {
        use_large_payload = true;
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_large_t);
    } else {
        use_large_payload = false;
        rsp_header_size = sizeof(pci_doe_spdm_vendor_defined_response_t);
    }
    if (spdm_response_size < rsp_header_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->pci_doe_vendor_header.len !=
        sizeof(spdm_response->pci_doe_vendor_header.vendor_id)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->pci_doe_vendor_header.vendor_id != vendor_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (use_large_payload) {
        rsp_payload_length = spdm_response_large->pci_doe_vendor_header.payload_length;
        rsp_pci_protocol = &spdm_response_large->pci_doe_vendor_header.pci_protocol;
    } else {
        rsp_payload_length = spdm_response->pci_doe_vendor_header.payload_length;
        rsp_pci_protocol = &spdm_response->pci_doe_vendor_header.pci_protocol;
    }

    if (rsp_pci_protocol->protocol_id !=
        pci_protocol.protocol_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_payload_length < sizeof(pci_protocol_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_payload_length - sizeof(pci_protocol_header_t) >
        spdm_response_size - rsp_header_size) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *response_size = rsp_payload_length - sizeof(pci_protocol_header_t);
    libspdm_copy_mem (response, *response_size, (uint8_t *)spdm_response + rsp_header_size, *response_size);
    /* clear the copied memory, because it may include secret */
    libspdm_zero_mem ((uint8_t *)spdm_response + rsp_header_size, *response_size);

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t pci_doe_spdm_vendor_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    pci_protocol_header_t pci_protocol,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    return pci_doe_spdm_vendor_send_receive_data_ex (
        spdm_context, session_id,
        SPDM_VENDOR_ID_PCISIG, pci_protocol,
        request, request_size,
        response, response_size
        );
}
