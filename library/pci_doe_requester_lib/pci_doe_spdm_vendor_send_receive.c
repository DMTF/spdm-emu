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
    libspdm_return_t status;
    uint8_t request_buffer[sizeof(pci_protocol_header_t) +
                           LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE];
    uint8_t response_buffer[sizeof(pci_protocol_header_t) +
                            LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE];
    uint32_t req_payload_length;
    uint8_t *req_payload;
    uint32_t rsp_payload_length;
    uint16_t rsp_standard_id;
    uint16_t rsp_vendor_id;
    uint8_t rsp_vendor_id_len;
    pci_protocol_header_t *rsp_pci_protocol;

    req_payload_length = (uint32_t)(sizeof(pci_protocol_header_t) + request_size);
    req_payload = (void *)request_buffer;
    libspdm_copy_mem(req_payload, sizeof(pci_protocol_header_t), &pci_protocol, sizeof(pci_protocol_header_t));
    req_payload += sizeof(pci_protocol_header_t);
    libspdm_copy_mem(req_payload, request_size, request, request_size);

    rsp_vendor_id_len = sizeof(uint16_t);
    rsp_payload_length = sizeof(response_buffer);

    status = libspdm_vendor_send_request_receive_response (
        spdm_context, session_id,
        SPDM_STANDARD_ID_PCISIG, sizeof(vendor_id), &vendor_id,
        req_payload_length, (void *)request_buffer,
        &rsp_standard_id, &rsp_vendor_id_len, &rsp_vendor_id,
        &rsp_payload_length, (void *)response_buffer
    );

    /* clear the copied memory, because it may include secret */
    libspdm_zero_mem ((uint8_t *)request_buffer, sizeof(request_buffer));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (rsp_standard_id != SPDM_STANDARD_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_vendor_id_len != sizeof(uint16_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_vendor_id != vendor_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    rsp_pci_protocol = (void *)response_buffer;

    if (rsp_pci_protocol->protocol_id !=
        pci_protocol.protocol_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_payload_length < sizeof(pci_protocol_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *response_size = rsp_payload_length - sizeof(pci_protocol_header_t);
    libspdm_copy_mem (response, *response_size, (uint8_t *)response_buffer + sizeof(pci_protocol_header_t), *response_size);
    /* clear the copied memory, because it may include secret */
    libspdm_zero_mem ((uint8_t *)response_buffer, rsp_payload_length);

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

