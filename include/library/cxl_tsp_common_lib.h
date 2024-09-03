/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_TSP_COMMON_LIB_H__
#define __CXL_TSP_COMMON_LIB_H__

#include "industry_standard/cxl_idekm.h"
#include "industry_standard/cxl_tsp.h"

#define LIBCXLTSP_MAX_VERSION_COUNT 0x1
#define LIBCXLTSP_CONFIGURATION_REPORT_MAX_SIZE 0x1000

#define LIBCXLTSP_CONFIGURATION_REPORT_PORTION_LEN 0x40

typedef struct {
    uint16_t memory_encryption_features_supported;
    uint32_t memory_encryption_algorithms_supported;
    uint16_t memory_encryption_number_of_range_based_keys;
    uint16_t te_state_change_and_access_control_features_supported;
    uint32_t supported_explicit_oob_te_state_granularity;
    uint32_t supported_explicit_ib_te_state_granularity;
    uint16_t configuration_features_supported;
    uint32_t number_of_ckids;
    uint8_t number_of_secondary_sessions;
} libcxltsp_device_capabilities_t;

typedef struct {
    uint16_t memory_encryption_features_enable;
    uint32_t memory_encryption_algorithm_select;
    uint16_t te_state_change_and_access_control_features_enable;
    uint32_t explicit_oob_te_state_granularity;
    uint16_t configuration_features_enable;
    uint32_t ckid_base;
    uint32_t number_of_ckids;
    cxl_tsp_explicit_ib_te_state_granularity_entry_t explicit_ib_te_state_granularity_entry[8];
} libcxltsp_device_configuration_t;

typedef struct {
    uint16_t configuration_validity_flags;
    uint8_t secondary_session_ckid_type;
    cxl_tsp_secondary_session_psk_key_material_t secondary_session_psk_key_material[4];
} libcxltsp_device_2nd_session_info_t;

#endif
