/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
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
libspdm_return_t cxl_tsp_set_configuration(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    const libcxltsp_device_configuration_t *device_configuration,
    const libcxltsp_device_2nd_session_info_t *device_2nd_session_info)
{
    libspdm_return_t status;
    cxl_tsp_set_target_configuration_req_t request;
    size_t request_size;
    uint8_t res_buf[LIBCXLTSP_ERROR_MESSAGE_MAX_SIZE];
    cxl_tsp_set_target_configuration_rsp_t *response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.tsp_version = CXL_TSP_MESSAGE_VERSION_10;
    request.header.op_code = CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION;

    request.memory_encryption_features_enable = device_configuration->memory_encryption_features_enable;
    request.memory_encryption_algorithm_select = device_configuration->memory_encryption_algorithm_select;
    request.te_state_change_and_access_control_features_enable = device_configuration->te_state_change_and_access_control_features_enable;
    request.explicit_oob_te_state_granularity = device_configuration->explicit_oob_te_state_granularity;
    request.configuration_features_enable = device_configuration->configuration_features_enable;
    request.ckid_base = device_configuration->ckid_base;
    request.number_of_ckids = device_configuration->number_of_ckids;
    libspdm_copy_mem (
        request.explicit_ib_te_state_granularity_entry,
        sizeof(request.explicit_ib_te_state_granularity_entry),
        device_configuration->explicit_ib_te_state_granularity_entry,
        sizeof(device_configuration->explicit_ib_te_state_granularity_entry));

    request.configuration_validity_flags = device_2nd_session_info->configuration_validity_flags;
    request.secondary_session_ckid_type = device_2nd_session_info->secondary_session_ckid_type;
    libspdm_copy_mem (
        request.secondary_session_psk_key_material,
        sizeof(request.secondary_session_psk_key_material),
        device_2nd_session_info->secondary_session_psk_key_material,
        sizeof(device_2nd_session_info->secondary_session_psk_key_material));

    request_size = sizeof(request);
    response = (void *)res_buf;
    response_size = sizeof(res_buf);
    status = cxl_tsp_send_receive_data(spdm_context, session_id,
                                       &request, request_size,
                                       response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(cxl_tsp_set_target_configuration_rsp_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response->header.tsp_version != request.header.tsp_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response->header.op_code != CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION_RSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
