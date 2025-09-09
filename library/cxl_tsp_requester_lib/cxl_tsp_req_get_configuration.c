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

static inline bool libspdm_onehot0(uint32_t mask)
{
    return !mask || !(mask & (mask - 1));
}

libspdm_return_t
cxl_tsp_validate_configruation (
    libcxltsp_device_configuration_t *device_configuration
    )
{
    uint16_t memory_encryption_features_enable;
    uint32_t memory_encryption_algorithm_select;
    uint16_t te_state_change_and_access_control_features_enable;
    uint32_t explicit_oob_te_state_granularity;
    cxl_tsp_explicit_ib_te_state_granularity_entry_t
        explicit_ib_te_state_granularity_entry[8];
    size_t index;
    uint8_t length_index_bit;

    memory_encryption_features_enable = device_configuration->memory_encryption_features_enable & 
        (CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED);
    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION) == 0) {
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION) != 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) == 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) == 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    memory_encryption_algorithm_select = device_configuration->memory_encryption_algorithm_select & 
        (CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_128 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_VENDOR_SPECIFIC);
    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION) == 0) {
        if (memory_encryption_algorithm_select != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (!libspdm_onehot0(memory_encryption_algorithm_select)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    te_state_change_and_access_control_features_enable = device_configuration->te_state_change_and_access_control_features_enable & 
        (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE);
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    explicit_oob_te_state_granularity = device_configuration->explicit_oob_te_state_granularity;
    if ((te_state_change_and_access_control_features_enable & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE) == 0) {
        if (explicit_oob_te_state_granularity != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if (!libspdm_onehot0(explicit_oob_te_state_granularity)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0) {
        if (device_configuration->ckid_base >= 0x2000) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if ((device_configuration->ckid_base + device_configuration->number_of_ckids) >= 0x2000) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    libspdm_copy_mem(
        explicit_ib_te_state_granularity_entry,
        sizeof(explicit_ib_te_state_granularity_entry),
        device_configuration->explicit_ib_te_state_granularity_entry,
        sizeof(device_configuration->explicit_ib_te_state_granularity_entry)
        );
    if ((te_state_change_and_access_control_features_enable & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE) != 0) {
        length_index_bit = 0;
        for (index = 0; index < 8; index++) {
            if (explicit_ib_te_state_granularity_entry[index].length_index == 0xff) {
                continue;
            }
            if (explicit_ib_te_state_granularity_entry[index].length_index > 7) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            if ((length_index_bit & (1 << explicit_ib_te_state_granularity_entry[index].length_index)) != 0) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            length_index_bit |= (1 << explicit_ib_te_state_granularity_entry[index].length_index);
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
            
        status = cxl_tsp_validate_configruation (device_configuration);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }
    *current_tsp_state = response.current_tsp_state;
    if (*current_tsp_state > CXL_TSP_STATE_ERROR) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
