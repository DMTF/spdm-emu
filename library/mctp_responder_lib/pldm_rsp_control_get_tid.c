/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_responder_lib.h"

/**
    Process the PLDM request and return the response.

    @param request       the PLDM request message, start from pldm_message_header_t.
    @param request_size  size in bytes of request.
    @param response      the PLDM response message, start from pldm_message_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pldm_get_response_control_get_tid (IN void *mctp_context,
    IN void *spdm_context, IN uint32_t *session_id,
    IN void *request, IN uintn request_size,
    OUT void *response, IN OUT uintn *response_size)
{
    pldm_get_tid_request_t *app_request;
    pldm_get_tid_response_t *app_response;

    app_request = request;
    if (request_size != sizeof(pldm_get_tid_request_t)) {
        return RETURN_INVALID_PARAMETER;
    }
    ASSERT (*response_size >= sizeof(pldm_get_tid_response_t));
    *response_size = sizeof(pldm_get_tid_response_t);

    zero_mem (response, *response_size);

    app_response = response;
    app_response->pldm_header.instance_id = app_request->pldm_header.instance_id & PLDM_HEADER_INSTANCE_ID_MASK;
    app_response->pldm_header.pldm_type = app_request->pldm_header.pldm_type; /* both version and type*/
    app_response->pldm_header.pldm_command_code = app_request->pldm_header.pldm_command_code;
    app_response->pldm_response_header.pldm_completion_code = PLDM_BASE_CODE_SUCCESS;

    /* TBD - need PLDM context to get the info*/
    app_response->tid = 1;

    return RETURN_SUCCESS;
}
