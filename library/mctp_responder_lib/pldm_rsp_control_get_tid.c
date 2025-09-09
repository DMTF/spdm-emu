/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_responder_lib.h"

/**
 *  Process the PLDM request and return the response.
 *
 *  @param request       the PLDM request message, start from pldm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the PLDM response message, start from pldm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pldm_get_response_control_get_tid (const void *mctp_context,
                                                    const void *spdm_context,
                                                    const uint32_t *session_id,
                                                    const void *request, size_t request_size,
                                                    void *response, size_t *response_size)
{
    const pldm_get_tid_request_t *app_request;
    pldm_get_tid_response_t *app_response;

    app_request = request;
    if (request_size != sizeof(pldm_get_tid_request_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size >= sizeof(pldm_get_tid_response_t));
    *response_size = sizeof(pldm_get_tid_response_t);

    libspdm_zero_mem (response, *response_size);

    app_response = response;
    app_response->pldm_header.instance_id = app_request->pldm_header.instance_id &
                                            PLDM_HEADER_INSTANCE_ID_MASK;
    app_response->pldm_header.pldm_type = app_request->pldm_header.pldm_type; /* both version and type*/
    app_response->pldm_header.pldm_command_code = app_request->pldm_header.pldm_command_code;
    app_response->pldm_response_header.pldm_completion_code = PLDM_BASE_CODE_SUCCESS;

    /* TBD - need PLDM context to get the info*/
    app_response->tid = 1;

    return LIBSPDM_STATUS_SUCCESS;
}
