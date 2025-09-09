/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_requester_lib.h"

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_start_interface(const void *pci_doe_context,
                                           void *spdm_context, const uint32_t *session_id,
                                           const pci_tdisp_interface_id_t *interface_id,
                                           const uint8_t *start_interface_nonce)
{
    libspdm_return_t status;
    pci_tdisp_start_interface_request_t request;
    size_t request_size;
    uint8_t res_buf[LIBTDISP_ERROR_MESSAGE_MAX_SIZE];
    pci_tdisp_start_interface_response_t *response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.version = PCI_TDISP_MESSAGE_VERSION_10;
    request.header.message_type = PCI_TDISP_START_INTERFACE_REQ;
    request.header.interface_id.function_id = interface_id->function_id;
    libspdm_copy_mem (request.start_interface_nonce, sizeof(request.start_interface_nonce),
                      start_interface_nonce, PCI_TDISP_START_INTERFACE_NONCE_SIZE);

    request_size = sizeof(request);
    response = (void *)res_buf;
    response_size = sizeof(res_buf);
    status = pci_tdisp_send_receive_data(spdm_context, session_id,
                                         &request, request_size,
                                         response, &response_size);
    libspdm_zero_mem (&request.start_interface_nonce, sizeof(request.start_interface_nonce));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(pci_tdisp_start_interface_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response->header.version != request.header.version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response->header.message_type != PCI_TDISP_START_INTERFACE_RSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response->header.interface_id.function_id != request.header.interface_id.function_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
