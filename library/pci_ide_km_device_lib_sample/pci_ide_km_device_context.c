/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_ide_km_device_lib.h"

libidekm_device_port_context g_idekm_device_port_context;

libidekm_device_port_context *libidekm_initialize_device_port_context (
    uint8_t port_index
    )
{
    libspdm_zero_mem (
        &g_idekm_device_port_context,
        sizeof(g_idekm_device_port_context)
        );
    g_idekm_device_port_context.port_index = port_index;
    g_idekm_device_port_context.dev_func_num = 0;
    g_idekm_device_port_context.bus_num = 0;
    g_idekm_device_port_context.segment = 0;
    g_idekm_device_port_context.max_port_index = 7;

    g_idekm_device_port_context.ide_reg_buffer_count = PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT;

    /* TBD: init the ide_reg_block */

    return &g_idekm_device_port_context;
}

libidekm_device_port_context *libidekm_get_device_port_context (
    uint8_t port_index
    )
{
    if (g_idekm_device_port_context.port_index == port_index) {
        return &g_idekm_device_port_context;
    } else {
        return NULL;
    }
}
