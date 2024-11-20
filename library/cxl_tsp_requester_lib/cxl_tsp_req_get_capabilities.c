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
#include "hal/library/debuglib.h"

libspdm_return_t
cxl_tsp_validate_capability (
    libcxltsp_device_capabilities_t *device_capabilities
    )
{
    uint16_t memory_encryption_features_supported;
    uint32_t memory_encryption_algorithms_supported;
    uint16_t te_state_change_and_access_control_features_supported;
    uint32_t supported_explicit_oob_te_state_granularity;
    uint32_t supported_explicit_ib_te_state_granularity;
    uint16_t configuration_features_supported;

    memory_encryption_features_supported = device_capabilities->memory_encryption_features_supported &
        (CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_RANGE_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_INITIATOR_SUPPLIED_ENTROPY |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED);
    if ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) == 0) {
        if (((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_RANGE_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED) != 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED) != 0) &&
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) == 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    memory_encryption_algorithms_supported = device_capabilities->memory_encryption_algorithms_supported &
        (CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_128 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_VENDOR_SPECIFIC);
    if ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) != 0) {
        if (memory_encryption_algorithms_supported == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    if ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_RANGE_BASED_ENCRYPTION) == 0) {
        if (device_capabilities->memory_encryption_number_of_range_based_keys != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (device_capabilities->memory_encryption_number_of_range_based_keys == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    te_state_change_and_access_control_features_supported = device_capabilities->te_state_change_and_access_control_features_supported & 
        (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE);
    if (((te_state_change_and_access_control_features_supported &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_supported &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (((te_state_change_and_access_control_features_supported &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_supported &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (((te_state_change_and_access_control_features_supported &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE) != 0) &&
        (((te_state_change_and_access_control_features_supported &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    supported_explicit_oob_te_state_granularity = device_capabilities->supported_explicit_oob_te_state_granularity;
    if ((te_state_change_and_access_control_features_supported & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE) == 0) {
        if (supported_explicit_oob_te_state_granularity != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (supported_explicit_oob_te_state_granularity == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    supported_explicit_ib_te_state_granularity = device_capabilities->supported_explicit_ib_te_state_granularity &
        (0x7FF | CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_ENTIRE_MEMORY);
    if ((te_state_change_and_access_control_features_supported & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE) == 0) {
        if (supported_explicit_ib_te_state_granularity != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (supported_explicit_ib_te_state_granularity == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    if ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) != 0) {
        if ((device_capabilities->number_of_ckids < 2) ||
            (device_capabilities->number_of_ckids >= 0x2000)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    configuration_features_supported = device_capabilities->configuration_features_supported &
        (CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_LOCKED_TARGET_FW_UPDATE |
         CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_TARGET_SUPPORT_ADDITIONAL_SPDM_SESSIONS);
    if ((configuration_features_supported & CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_TARGET_SUPPORT_ADDITIONAL_SPDM_SESSIONS) == 0) {
        if (device_capabilities->number_of_secondary_sessions != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if ((device_capabilities->number_of_secondary_sessions == 0) ||
            (device_capabilities->number_of_secondary_sessions > 4)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

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
libspdm_return_t cxl_tsp_get_capabilities(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_capabilities_t *device_capabilities)
{
    libspdm_return_t status;
    cxl_tsp_get_target_capabilities_req_t request;
    size_t request_size;
    cxl_tsp_get_target_capabilities_rsp_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.tsp_version = CXL_TSP_MESSAGE_VERSION_10;
    request.header.op_code = CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = cxl_tsp_send_receive_data(spdm_context, session_id,
                                       &request, request_size,
                                       &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(cxl_tsp_get_target_capabilities_rsp_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response.header.tsp_version != request.header.tsp_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.header.op_code != CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES_RSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    device_capabilities->memory_encryption_features_supported = response.memory_encryption_features_supported;
    device_capabilities->memory_encryption_algorithms_supported = response.memory_encryption_algorithms_supported;
    device_capabilities->memory_encryption_number_of_range_based_keys = response.memory_encryption_number_of_range_based_keys;
    device_capabilities->te_state_change_and_access_control_features_supported = response.te_state_change_and_access_control_features_supported;
    device_capabilities->supported_explicit_oob_te_state_granularity = response.supported_explicit_oob_te_state_granularity;
    device_capabilities->supported_explicit_ib_te_state_granularity = response.supported_explicit_ib_te_state_granularity;
    device_capabilities->configuration_features_supported = response.configuration_features_supported;
    device_capabilities->number_of_ckids = response.number_of_ckids;
    device_capabilities->number_of_secondary_sessions = response.number_of_secondary_sessions;

    status = cxl_tsp_validate_capability (device_capabilities);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
