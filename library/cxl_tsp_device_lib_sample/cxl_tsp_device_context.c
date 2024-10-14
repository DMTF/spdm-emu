/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

libcxltsp_device_context g_cxltsp_device_context;

libcxltsp_device_context *libcxltsp_initialize_device_context (
    const void *pci_doe_context
    )
{
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
