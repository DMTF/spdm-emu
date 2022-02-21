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

typedef struct {
    pldm_dispatch_type_t                   dispatch_type;
    pldm_get_secured_app_request_func_t    func;
} pldm_secured_app_dispatch_struct_t;

pldm_secured_app_dispatch_struct_t m_pldm_secured_app_dispatch[] = {
   {{PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY, PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID}, pldm_get_response_control_get_tid },
};

/**
    Process the PLDM request and return the response.

    @param request       the PLDM request message, start from pldm_message_header_t.
    @param request_size  size in bytes of request.
    @param response      the PLDM response message, start from pldm_message_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pldm_get_response_secured_app_request(const void *mctp_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, uintn request_size,
    void *response, uintn *response_size)
{
    const pldm_message_header_t *app_request;
    uintn index;

    app_request = request;
    if (request_size < sizeof(pldm_message_header_t)) {
        return RETURN_INVALID_PARAMETER;
    }
    if ((app_request->instance_id & PLDM_HEADER_REQUEST_MASK) == 0) {
        return RETURN_INVALID_PARAMETER;
    }
    if ((app_request->pldm_type & PLDM_HEADER_VERSION_MASK) != PLDM_HEADER_VERSION) {
        return RETURN_INVALID_PARAMETER;
    }

    for (index = 0; index < ARRAY_SIZE(m_pldm_secured_app_dispatch); index++) {
        if (((app_request->pldm_type & PLDM_HEADER_TYPE_MASK) == m_pldm_secured_app_dispatch[index].dispatch_type.pldm_type) &&
            (app_request->pldm_command_code == m_pldm_secured_app_dispatch[index].dispatch_type.pldm_command_code)) {
            return m_pldm_secured_app_dispatch[index].func (
                        mctp_context, spdm_context, session_id,
                        request, request_size, response, response_size);
        }
    }

    return RETURN_INVALID_PARAMETER;
}
