/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_ide_km_device_lib.h"

libcxlidekm_device_port_context g_cxlidekm_device_port_context;

libcxlidekm_device_port_context *libcxlidekm_initialize_device_port_context (
    uint8_t port_index
    )
{
    libspdm_zero_mem (
        &g_cxlidekm_device_port_context,
        sizeof(g_cxlidekm_device_port_context)
        );
    g_cxlidekm_device_port_context.port_index = port_index;
    g_cxlidekm_device_port_context.dev_func_num = 0;
    g_cxlidekm_device_port_context.bus_num = 0;
    g_cxlidekm_device_port_context.segment = 0;
    g_cxlidekm_device_port_context.max_port_index = 7;
    g_cxlidekm_device_port_context.caps = CXL_IDE_KM_QUERY_RESP_CAP_VERSION_1 |
                                          CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP |
                                          CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP |
                                          CXL_IDE_KM_QUERY_RESP_K_SET_STOP_CAP;
    g_cxlidekm_device_port_context.ide_reg_buffer_count = CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT;

    /* TBD: init the ide_reg_block */

    return &g_cxlidekm_device_port_context;
}

libcxlidekm_device_port_context *libcxlidekm_get_device_port_context (
    uint8_t port_index
    )
{
    if (g_cxlidekm_device_port_context.port_index == port_index) {
        return &g_cxlidekm_device_port_context;
    } else {
        return NULL;
    }
}
