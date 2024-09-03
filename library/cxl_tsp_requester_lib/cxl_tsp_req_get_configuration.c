/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_requester_lib.h"

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TSP request is sent and response is received.
 * @return ERROR                        The TSP response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_configuration(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_configuration_t *device_configuration,
    uint8_t *current_tsp_state)
{
    libspdm_return_t status;
    cxl_tsp_get_target_configuration_req_t request;
    size_t request_size;
    cxl_tsp_get_target_configuration_rsp_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.tsp_version = CXL_TSP_MESSAGE_VERSION_10;
    request.header.op_code = CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = cxl_tsp_send_receive_data(spdm_context, session_id,
                                       &request, request_size,
                                       &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(cxl_tsp_get_target_configuration_rsp_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response.header.tsp_version != request.header.tsp_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.header.op_code != CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_RSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (device_configuration != NULL) {
        device_configuration->memory_encryption_features_enable = response.memory_encryption_features_enabled;
        device_configuration->memory_encryption_algorithm_select = response.memory_encryption_algorithm_selected;
        device_configuration->te_state_change_and_access_control_features_enable = response.te_state_change_and_access_control_features_enabled;
        device_configuration->explicit_oob_te_state_granularity = response.explicit_oob_te_state_granularity_enabled;
        device_configuration->configuration_features_enable = response.configuration_features_enabled;
        device_configuration->ckid_base = response.ckid_base;
        device_configuration->number_of_ckids = response.number_of_ckids;
        libspdm_copy_mem (
            device_configuration->explicit_ib_te_state_granularity_entry,
            sizeof(device_configuration->explicit_ib_te_state_granularity_entry),
            response.explicit_ib_te_state_granularity_entry,
            sizeof(response.explicit_ib_te_state_granularity_entry));
    }
    *current_tsp_state = response.current_tsp_state;

    return LIBSPDM_STATUS_SUCCESS;
}
