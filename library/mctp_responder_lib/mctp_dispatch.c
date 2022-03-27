/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_responder_lib.h"

typedef struct {
    mctp_message_header_t header;
    mctp_get_secured_app_request_func_t func;
} mctp_secured_app_dispatch_struct_t;

mctp_secured_app_dispatch_struct_t m_mctp_secured_app_dispatch[] = {
    {{MCTP_MESSAGE_TYPE_PLDM}, pldm_get_response_secured_app_request },
};

/**
 *  Process the MCTP request and return the response.
 *
 *  @param request       the MCTP request message, start from mctp_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the MCTP response message, start from mctp_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t mctp_get_response_secured_app_request(const void *mctp_context,
                                                    void *spdm_context, const uint32_t *session_id,
                                                    const void *request, size_t request_size,
                                                    void *response, size_t *response_size)
{
    const mctp_message_header_t *app_request;
    mctp_message_header_t *app_response;
    size_t index;
    size_t app_response_size;
    libspdm_return_t status;

    app_request = request;
    app_response = response;
    if (request_size < sizeof(mctp_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size > sizeof(mctp_message_header_t));
    app_response_size = *response_size - sizeof(mctp_message_header_t);

    for (index = 0; index < ARRAY_SIZE(m_mctp_secured_app_dispatch); index++) {
        if (app_request->message_type == m_mctp_secured_app_dispatch[index].header.message_type) {
            status = m_mctp_secured_app_dispatch[index].func (
                mctp_context, spdm_context, session_id,
                (uint8_t *)request + sizeof(mctp_message_header_t),
                request_size - sizeof(mctp_message_header_t),
                (uint8_t *)response + sizeof(mctp_message_header_t),
                &app_response_size
                );
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }

            libspdm_zero_mem (app_response, sizeof(mctp_message_header_t));
            app_response->message_type = app_request->message_type;

            *response_size = app_response_size + sizeof(mctp_message_header_t);

            return LIBSPDM_STATUS_SUCCESS;
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
