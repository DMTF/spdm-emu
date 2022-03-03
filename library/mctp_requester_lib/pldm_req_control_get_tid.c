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

return_status pldm_control_get_tid(const void *mctp_context,
                    void *spdm_context, const uint32_t *session_id, uint8_t *tid)
{
    return_status status;
    pldm_get_tid_request_t app_request;
    pldm_get_tid_response_t app_response;
    uintn app_response_size;
    uint8_t instance_id = 0;

    libspdm_zero_mem (&app_request, sizeof(app_request));
    app_request.pldm_header.instance_id = instance_id | PLDM_HEADER_REQUEST_MASK;
    app_request.pldm_header.pldm_type = PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY;
    app_request.pldm_header.pldm_command_code = PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID;

    app_response_size = sizeof(app_response);
    status = pldm_send_receive_data(mctp_context,
                        spdm_context, session_id,
                        &app_request,
                        sizeof(app_request),
                        &app_response,
                        &app_response_size);
    if (RETURN_ERROR(status)) {
        return status;
    }

    if (app_response_size != sizeof(app_response)) {
        return RETURN_DEVICE_ERROR;
    }
    if ((app_response.pldm_header.instance_id & PLDM_HEADER_REQUEST_MASK) != 0) {
        return RETURN_DEVICE_ERROR;
    }
    if ((app_response.pldm_header.instance_id & PLDM_HEADER_DATAGRAM_MASK) != 0) {
        return RETURN_DEVICE_ERROR;
    }
    if ((app_response.pldm_header.instance_id & PLDM_HEADER_INSTANCE_ID_MASK) != instance_id) {
        return RETURN_DEVICE_ERROR;
    }
    if ((app_response.pldm_header.pldm_type & PLDM_HEADER_VERSION_MASK) != PLDM_HEADER_VERSION) {
        return RETURN_DEVICE_ERROR;
    }
    if ((app_response.pldm_header.pldm_type & PLDM_HEADER_TYPE_MASK) !=
               PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY) {
        return RETURN_DEVICE_ERROR;
    }
    if (app_response.pldm_header.pldm_command_code !=
               PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID) {
        return RETURN_DEVICE_ERROR;
    }
    if (app_response.pldm_response_header.pldm_completion_code !=
               PLDM_BASE_CODE_SUCCESS) {
        return RETURN_DEVICE_ERROR;
    }

    return RETURN_SUCCESS;
}
