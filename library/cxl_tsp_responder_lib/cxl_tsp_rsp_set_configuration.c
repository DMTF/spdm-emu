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

static inline bool libspdm_onehot0(uint32_t mask)
{
    return !mask || !(mask & (mask - 1));
}

libcxltsp_error_code_t
cxl_tsp_validate_configruation (
    const cxl_tsp_set_target_configuration_req_t *tsp_request,
    const libcxltsp_device_capabilities_t *device_capabilities
    )
{
    uint16_t memory_encryption_features_enable;
    uint16_t memory_encryption_features_supported;
    uint32_t memory_encryption_algorithm_select;
    uint32_t memory_encryption_algorithms_supported;
    uint16_t te_state_change_and_access_control_features_enable;
    uint16_t te_state_change_and_access_control_features_supported;
    uint32_t explicit_oob_te_state_granularity;
    uint32_t supported_explicit_oob_te_state_granularity;
    cxl_tsp_explicit_ib_te_state_granularity_entry_t
        explicit_ib_te_state_granularity_entry[8];
    uint32_t supported_explicit_ib_te_state_granularity;
    size_t index;
    uint8_t length_index_bit;
    uint8_t number_of_secondary_sessions;

    memory_encryption_features_enable = tsp_request->memory_encryption_features_enable & 
        (CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION |
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED);
    memory_encryption_features_supported = device_capabilities->memory_encryption_features_supported;
    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION) == 0) {
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION) != 0) ||
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    } else {
        if ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) == 0) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) == 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_RANGE_BASED_ENCRYPTION) == 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0) &&
            ((memory_encryption_features_supported & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED) == 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }

        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION) != 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) == 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0) &&
            ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) == 0)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    }

    memory_encryption_algorithm_select = tsp_request->memory_encryption_algorithm_select & 
        (CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_128 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256 |
         CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_VENDOR_SPECIFIC);
    memory_encryption_algorithms_supported = device_capabilities->memory_encryption_algorithms_supported;
    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION) == 0) {
        if (memory_encryption_algorithm_select != 0) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    } else {
        if (!libspdm_onehot0(memory_encryption_algorithm_select)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if ((memory_encryption_algorithm_select & memory_encryption_algorithms_supported) == 0) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    }

    te_state_change_and_access_control_features_enable = tsp_request->te_state_change_and_access_control_features_enable & 
        (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE |
         CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE);
    te_state_change_and_access_control_features_supported = device_capabilities->te_state_change_and_access_control_features_supported;
    if ((te_state_change_and_access_control_features_enable & te_state_change_and_access_control_features_supported) !=
        te_state_change_and_access_control_features_enable) {
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }
    if (((te_state_change_and_access_control_features_enable &
          CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE) != 0) &&
        (((te_state_change_and_access_control_features_enable &
           (CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE |
            CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE))) == 0)) {
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }

    explicit_oob_te_state_granularity = tsp_request->explicit_oob_te_state_granularity;
    supported_explicit_oob_te_state_granularity = device_capabilities->supported_explicit_oob_te_state_granularity;
    if ((te_state_change_and_access_control_features_enable & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE) == 0) {
        if (explicit_oob_te_state_granularity != 0) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    } else {
        if (!libspdm_onehot0(explicit_oob_te_state_granularity)) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if ((explicit_oob_te_state_granularity & supported_explicit_oob_te_state_granularity) == 0) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    }

    if ((memory_encryption_features_enable & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED) != 0) {
        if (tsp_request->number_of_ckids > device_capabilities->number_of_ckids) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if (tsp_request->ckid_base >= 0x2000) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
        if ((tsp_request->ckid_base + tsp_request->number_of_ckids) >= 0x2000) {
            return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
        }
    }

    libspdm_copy_mem(
        explicit_ib_te_state_granularity_entry,
        sizeof(explicit_ib_te_state_granularity_entry),
        tsp_request->explicit_ib_te_state_granularity_entry,
        sizeof(tsp_request->explicit_ib_te_state_granularity_entry)
        );
    supported_explicit_ib_te_state_granularity = device_capabilities->supported_explicit_ib_te_state_granularity;
    if ((te_state_change_and_access_control_features_enable & CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE) != 0) {
        length_index_bit = 0;
        for (index = 0; index < 8; index++) {
            if (explicit_ib_te_state_granularity_entry[index].length_index == 0xff) {
                continue;
            }
            if (explicit_ib_te_state_granularity_entry[index].length_index > 7) {
                return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
            }
            if (((supported_explicit_ib_te_state_granularity & CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_ENTIRE_MEMORY) != 0) &&
                (explicit_ib_te_state_granularity_entry[index].length_index == 7)) {
                return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
            }
            if ((length_index_bit & (1 << explicit_ib_te_state_granularity_entry[index].length_index)) != 0) {
                return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
            }
            length_index_bit |= (1 << explicit_ib_te_state_granularity_entry[index].length_index);
        }
    }

    switch (tsp_request->configuration_validity_flags) {
    case 0:
        number_of_secondary_sessions = 0;
        break;
    case 0x1:
        number_of_secondary_sessions = 1;
        break;
    case 0x3:
        number_of_secondary_sessions = 2;
        break;
    case 0x7:
        number_of_secondary_sessions = 3;
        break;
    case 0xF:
        number_of_secondary_sessions = 4;
        break;
    default:
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }
    if (number_of_secondary_sessions > device_capabilities->number_of_secondary_sessions) {
        return CXL_TSP_ERROR_CODE_INVALID_REQUEST;
    }

    return CXL_TSP_ERROR_CODE_SUCCESS;
}

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
libspdm_return_t cxl_tsp_get_response_set_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    const cxl_tsp_set_target_configuration_req_t *tsp_request;
    cxl_tsp_set_target_configuration_rsp_t *tsp_response;
    libcxltsp_error_code_t error_code;
    libcxltsp_device_configuration_t device_configuration;
    libcxltsp_device_2nd_session_info_t device_2nd_session_info;
    libcxltsp_device_capabilities_t device_capabilities;
    uint8_t current_tsp_state;

    tsp_request = request;
    tsp_response = response;
    if (request_size != sizeof(cxl_tsp_set_target_configuration_req_t)) {
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

    LIBSPDM_ASSERT (*response_size >= sizeof(cxl_tsp_set_target_configuration_rsp_t));
    libspdm_zero_mem (response, *response_size);

    /* get device capability and current configuration */
    error_code = cxl_tsp_device_get_capabilities (
        pci_doe_context, spdm_context, session_id,
        &device_capabilities);
    if (error_code != CXL_TSP_ERROR_CODE_SUCCESS) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, error_code, 0,
            response, response_size);
    }
    error_code = cxl_tsp_device_get_configuration (
        pci_doe_context, spdm_context, session_id,
        NULL,
        &current_tsp_state);
    if (error_code != CXL_TSP_ERROR_CODE_SUCCESS) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, error_code, 0,
            response, response_size);
    }
    if (current_tsp_state != CXL_TSP_STATE_CONFIG_UNLOCKED) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, CXL_TSP_ERROR_CODE_INVALID_SECURITY_STATE, 0,
            response, response_size);
    }
    /* validate the configuration */
    error_code = cxl_tsp_validate_configruation (
        tsp_request, &device_capabilities);
    if (error_code != CXL_TSP_ERROR_CODE_SUCCESS) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, error_code, 0,
            response, response_size);
    }

    device_configuration.memory_encryption_features_enable = tsp_request->memory_encryption_features_enable;
    device_configuration.memory_encryption_algorithm_select = tsp_request->memory_encryption_algorithm_select;
    device_configuration.te_state_change_and_access_control_features_enable = tsp_request->te_state_change_and_access_control_features_enable;
    device_configuration.explicit_oob_te_state_granularity = tsp_request->explicit_oob_te_state_granularity;
    device_configuration.configuration_features_enable = tsp_request->configuration_features_enable;
    device_configuration.ckid_base = tsp_request->ckid_base;
    device_configuration.number_of_ckids = tsp_request->number_of_ckids;
    libspdm_copy_mem (
        device_configuration.explicit_ib_te_state_granularity_entry,
        sizeof(device_configuration.explicit_ib_te_state_granularity_entry),
        tsp_request->explicit_ib_te_state_granularity_entry,
        sizeof(tsp_request->explicit_ib_te_state_granularity_entry));

    device_2nd_session_info.configuration_validity_flags = tsp_request->configuration_validity_flags;
    device_2nd_session_info.secondary_session_ckid_type = tsp_request->secondary_session_ckid_type;
    libspdm_copy_mem (
        device_2nd_session_info.secondary_session_psk_key_material,
        sizeof(device_2nd_session_info.secondary_session_psk_key_material),
        tsp_request->secondary_session_psk_key_material,
        sizeof(tsp_request->secondary_session_psk_key_material));

    error_code = cxl_tsp_device_set_configuration (
        pci_doe_context, spdm_context, session_id,
        &device_configuration,
        &device_2nd_session_info);
    if (error_code != CXL_TSP_ERROR_CODE_SUCCESS) {
        return cxl_tsp_get_response_error (
            pci_doe_context, spdm_context, session_id,
            request, error_code, 0,
            response, response_size);
    }

    *response_size = sizeof(cxl_tsp_set_target_configuration_rsp_t);

    tsp_response->header.tsp_version = tsp_request->header.tsp_version;
    tsp_response->header.op_code = CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION_RSP;

    return LIBSPDM_STATUS_SUCCESS;
}
