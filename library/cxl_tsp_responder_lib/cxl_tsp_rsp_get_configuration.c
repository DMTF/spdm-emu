/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

/**
 *  Process the TSP request and return the response.
 *
 *  @param request       the TSP request message, start from cxl_tsp_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the TSP response message, start from cxl_tsp_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_tsp_get_response_get_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    const cxl_tsp_get_target_configuration_req_t *tsp_request;
    cxl_tsp_get_target_configuration_rsp_t *tsp_response;
    libcxltsp_error_code_t error_code;
    libcxltsp_device_configuration_t device_configuration;
    uint8_t current_tsp_state;

    if (session_id == NULL) {
        return CXL_TSP_ERROR_CODE_NO_PRIVILEGE;
    }
    if (libcxltsp_get_session_type(*session_id) == LIB_CXL_TSP_SESSION_TYPE_OTHER) {
        return CXL_TSP_ERROR_CODE_NO_PRIVILEGE;
    }

    tsp_request = request;
    tsp_response = response;
    if (request_size != sizeof(cxl_tsp_get_target_configuration_req_t)) {
        return cxl_tsp_get_response_error (
            pci_doe_context,
            spdm_context, session_id,
            request, CXL_TSP_ERROR_CODE_INVALID_REQUEST, 0,
            response, response_size);
    }
    if (tsp_request->header.tsp_version != CXL_TSP_MESSAGE_VERSION_10) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, CXL_TSP_ERROR_CODE_VERSION_MISMATCH, 0,
            response, response_size);
    }

    LIBSPDM_ASSERT (*response_size >= sizeof(cxl_tsp_get_target_configuration_rsp_t));
    libspdm_zero_mem (response, *response_size);

    error_code = cxl_tsp_device_get_configuration (
        pci_doe_context, spdm_context, session_id,
        &device_configuration,
        &current_tsp_state);
    if (error_code != CXL_TSP_ERROR_CODE_SUCCESS) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, error_code, 0,
            response, response_size);
    }
    if ((current_tsp_state != CXL_TSP_STATE_CONFIG_UNLOCKED) &&
        (current_tsp_state != CXL_TSP_STATE_CONFIG_LOCKED)) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, CXL_TSP_ERROR_CODE_INVALID_SECURITY_STATE, 0,
            response, response_size);
    }

    *response_size = sizeof(cxl_tsp_get_target_configuration_rsp_t);

    tsp_response->header.tsp_version = tsp_request->header.tsp_version;
    tsp_response->header.op_code = CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_RSP;

    tsp_response->memory_encryption_features_enabled = device_configuration.memory_encryption_features_enable;
    tsp_response->memory_encryption_algorithm_selected = device_configuration.memory_encryption_algorithm_select;
    tsp_response->te_state_change_and_access_control_features_enabled = device_configuration.te_state_change_and_access_control_features_enable;
    tsp_response->explicit_oob_te_state_granularity_enabled = device_configuration.explicit_oob_te_state_granularity;
    tsp_response->configuration_features_enabled = device_configuration.configuration_features_enable;
    tsp_response->ckid_base = device_configuration.ckid_base;
    tsp_response->number_of_ckids = device_configuration.number_of_ckids;
    libspdm_copy_mem (
        tsp_response->explicit_ib_te_state_granularity_entry,
        sizeof(tsp_response->explicit_ib_te_state_granularity_entry),
        device_configuration.explicit_ib_te_state_granularity_entry,
        sizeof(device_configuration.explicit_ib_te_state_granularity_entry));

    tsp_response->current_tsp_state = current_tsp_state;

    return LIBSPDM_STATUS_SUCCESS;
}
