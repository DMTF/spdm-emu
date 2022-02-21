/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_requester_lib.h"

/**
  Send and receive an PLDM message

  @param  spdm_context                 A pointer to the SPDM context.
  @param  session_id                   Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param request                       the PLDM request message, start from pldm_message_header_t.
  @param request_size                  size in bytes of request.
  @param response                      the PLDM response message, start from pldm_message_header_t.
  @param response_size                 size in bytes of response.

  @retval RETURN_SUCCESS               The PLDM request is sent and response is received.
  @return ERROR                        The PLDM response is not received correctly.
**/
return_status pldm_send_receive_data (const void *mctp_context,
                    void *spdm_context, const uint32_t *session_id,
                    const void *request, uintn request_size,
                    void *response, uintn *response_size)
{
    return_status status;
    mctp_message_header_t mctp_header;

    mctp_header.message_type = MCTP_MESSAGE_TYPE_PLDM;
    status = mctp_send_receive_data (mctp_context, spdm_context, session_id,
                    mctp_header,
                    request, request_size, response, response_size);
    if (RETURN_ERROR(status)) {
        return status;
    }

    return RETURN_SUCCESS;
}