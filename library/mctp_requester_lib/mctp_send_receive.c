/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_requester_lib.h"

/**
 * Send and receive an MCTP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the MCTP request message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the MCTP response message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval RETURN_SUCCESS               The MCTP request is sent and response is received.
 * @return ERROR                        The MCTP response is not received correctly.
 **/
return_status mctp_send_receive_data (const void *mctp_context,
                                      void *spdm_context, const uint32_t *session_id,
                                      mctp_message_header_t mctp_header,
                                      const void *request, size_t request_size,
                                      void *response, size_t *response_size)
{
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;
    size_t data_size;
    return_status status;
    uint8_t request_buffer[sizeof(mctp_message_header_t) + MCTP_MAX_MESSAGE_SIZE];
    mctp_message_header_t *mctp_request;
    size_t mctp_request_size;
    uint8_t response_buffer[sizeof(mctp_message_header_t) + MCTP_MAX_MESSAGE_SIZE];
    mctp_message_header_t *mctp_response;
    size_t mctp_response_size;

    mctp_request = (void *)request_buffer;
    mctp_response = (void *)response_buffer;
    LIBSPDM_ASSERT (request_size <= MCTP_MAX_MESSAGE_SIZE);
    LIBSPDM_ASSERT (*response_size < MCTP_MAX_MESSAGE_SIZE);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&spdm_version, sizeof(spdm_version));
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version, &data_size);

    libspdm_zero_mem(mctp_request, sizeof(mctp_message_header_t));
    mctp_request->message_type = mctp_header.message_type;
    libspdm_copy_mem(mctp_request + 1, request_size, request, request_size);

    mctp_request_size = sizeof(mctp_message_header_t) + request_size;
    mctp_response_size = sizeof(mctp_message_header_t) + (*response_size);
    status = libspdm_send_receive_data(spdm_context, session_id,
                                       true, mctp_request, mctp_request_size,
                                       mctp_response, &mctp_response_size);
    if (RETURN_ERROR(status)) {
        return status;
    }

    if (mctp_response_size < sizeof(mctp_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (mctp_response->message_type != mctp_request->message_type) {
        return RETURN_DEVICE_ERROR;
    }

    *response_size = mctp_response_size - sizeof(mctp_message_header_t);
    libspdm_copy_mem (response, *response_size, mctp_response + 1, *response_size);

    return RETURN_SUCCESS;
}
