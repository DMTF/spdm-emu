/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

extern void *m_pci_doe_context;
extern void *m_mctp_context;

/**
 * Process a packet in the current SPDM session.
 *
 * @param  This                         Indicates a pointer to the calling context.
 * @param  session_id                    ID of the session.
 * @param  request                      A pointer to the request data.
 * @param  request_size                  size of the request data.
 * @param  response                     A pointer to the response data.
 * @param  response_size                 size of the response data. On input, it means the size of data
 *                                     buffer. On output, it means the size of copied data buffer if
 *                                     LIBSPDM_STATUS_SUCCESS, and means the size of desired data buffer if
 *                                     RETURN_BUFFER_TOO_SMALL.
 *
 * @retval LIBSPDM_STATUS_SUCCESS                  The SPDM request is set successfully.
 * @retval RETURN_INVALID_PARAMETER        The data_size is NULL or the data is NULL and *data_size is not zero.
 * @retval RETURN_UNSUPPORTED              The data_type is unsupported.
 * @retval RETURN_NOT_FOUND                The data_type cannot be found.
 * @retval RETURN_NOT_READY                The data_type is not ready to return.
 * @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
 * @retval RETURN_TIME                 A timeout occurred while waiting for the SPDM request
 *                                        to execute.
 **/
libspdm_return_t spdm_get_response_vendor_defined_request(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    libspdm_return_t status;

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        LIBSPDM_ASSERT(!is_app_message);
        status = pci_doe_get_response_spdm_vendor_defined_request (
            m_pci_doe_context, spdm_context, session_id,
            request, request_size, response, response_size);
    }

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        LIBSPDM_ASSERT(is_app_message);
        status = mctp_get_response_secured_app_request (
            m_mctp_context, spdm_context, session_id,
            request, request_size, response, response_size);
    }

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_generate_error_response(spdm_context,
                                        SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                        response_size, response);
    }
    return LIBSPDM_STATUS_SUCCESS;
}
