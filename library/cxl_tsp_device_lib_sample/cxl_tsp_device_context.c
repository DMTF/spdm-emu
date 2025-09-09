/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

libcxltsp_device_context g_cxltsp_device_context;

extern uint8_t m_cxl_tsp_current_psk_session_index;

bool libcxltsp_is_session_primary (uint32_t session_id)
{
    if (g_cxltsp_device_context.session_id_primary_valid &&
        (g_cxltsp_device_context.session_id_primary == session_id)) {
        return true;
    }
    return false;
}

bool libcxltsp_is_session_secondary (uint32_t session_id)
{
    size_t index;

    for (index = 0; index < 4; index++) {
        if (g_cxltsp_device_context.session_id_secondary_valid[index] &&
            (g_cxltsp_device_context.session_id_secondary[index] == session_id)) {
            return true;
        }
    }
    return false;
}

libcxltsp_session_type libcxltsp_get_session_type (uint32_t session_id)
{
    if (libcxltsp_is_session_primary(session_id)) {
        return LIB_CXL_TSP_SESSION_TYPE_PRIMARY;
    } else if (libcxltsp_is_session_secondary(session_id)) {
        return LIB_CXL_TSP_SESSION_TYPE_SECONDARY;
    }
    return LIB_CXL_TSP_SESSION_TYPE_OTHER;
}

void libcxltsp_set_session_id (uint32_t session_id, bool is_secondary, size_t session_index)
{
    if (!is_secondary) {
        g_cxltsp_device_context.session_id_primary_valid = true;
        g_cxltsp_device_context.session_id_primary = session_id;
    } else {
        LIBSPDM_ASSERT (session_index < 4);
        g_cxltsp_device_context.session_id_secondary_valid[session_index] = true;
        g_cxltsp_device_context.session_id_secondary[session_index] = session_id;
    }
}

void libcxltsp_initialize_session_id (
    void *spdm_context,
    uint32_t session_id
    )
{
    libspdm_data_parameter_t parameter;
    bool is_psk;
    size_t data_size;

    if (!g_cxltsp_device_context.session_id_primary_valid) {
        libcxltsp_set_session_id (session_id, false, 0);
        return ;
    }

    is_psk = false;
    data_size = sizeof(is_psk);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = session_id;
    libspdm_get_data (spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter, &is_psk, &data_size);
    if (!is_psk) {
        return ;
    }
    if (m_cxl_tsp_current_psk_session_index >= 4) {
        return ;
    }
    libcxltsp_set_session_id (session_id, true, m_cxl_tsp_current_psk_session_index);
    return ;
}

libcxltsp_device_context *libcxltsp_initialize_device_context (
    const void *pci_doe_context
    )
{
    if (g_cxltsp_device_context.session_id_primary_valid) {
        return &g_cxltsp_device_context;
    }

    libspdm_zero_mem (
        &g_cxltsp_device_context,
        sizeof(g_cxltsp_device_context)
        );

    g_cxltsp_device_context.supported_tsp_versions[0] = CXL_TSP_MESSAGE_VERSION_10;
    g_cxltsp_device_context.supported_tsp_versions_count = 1;

    g_cxltsp_device_context.device_capabilities.memory_encryption_features_supported =
        CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION;
    g_cxltsp_device_context.device_capabilities.memory_encryption_algorithms_supported =
        CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256;
    g_cxltsp_device_context.device_capabilities.memory_encryption_number_of_range_based_keys = 0;
    g_cxltsp_device_context.device_capabilities.te_state_change_and_access_control_features_supported =
        CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL |
        CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE |
        CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE;
    g_cxltsp_device_context.device_capabilities.supported_explicit_oob_te_state_granularity = 0;
    g_cxltsp_device_context.device_capabilities.supported_explicit_ib_te_state_granularity =
        CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_64B;
    g_cxltsp_device_context.device_capabilities.configuration_features_supported =
        CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_LOCKED_TARGET_FW_UPDATE |
        CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_TARGET_SUPPORT_ADDITIONAL_SPDM_SESSIONS;
    g_cxltsp_device_context.device_capabilities.number_of_ckids = 0;
    g_cxltsp_device_context.device_capabilities.number_of_secondary_sessions = 1;

    return &g_cxltsp_device_context;
}

libcxltsp_device_context *libcxltsp_get_device_context (
    const void *pci_doe_context
    )
{
    return &g_cxltsp_device_context;
}
