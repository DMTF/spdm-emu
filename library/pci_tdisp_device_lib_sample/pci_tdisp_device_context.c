/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_device_lib.h"

libtdisp_interface_context g_tdisp_interface_context;

libtdisp_interface_context *libtdisp_initialize_interface_context (
    const pci_tdisp_interface_id_t *interface_id
    )
{
    libspdm_zero_mem (
        &g_tdisp_interface_context,
        sizeof(g_tdisp_interface_context)
        );
    libspdm_copy_mem (
        &g_tdisp_interface_context.interface_id,
        sizeof(g_tdisp_interface_context.interface_id),
        interface_id,
        sizeof(*interface_id)
        );
    g_tdisp_interface_context.supported_tdisp_versions_count = 1;
    g_tdisp_interface_context.supported_tdisp_versions[0] = PCI_TDISP_MESSAGE_VERSION_10;

    g_tdisp_interface_context.tdisp_rsp_caps.dsm_caps = 0;
    g_tdisp_interface_context.tdisp_rsp_caps.req_msg_supported[0] = 0x7F;
    g_tdisp_interface_context.tdisp_rsp_caps.lock_interface_flags_supported =
                                             PCI_TDISP_LOCK_INTERFACE_FLAGS_NO_FW_UPDATE |
                                             PCI_TDISP_LOCK_INTERFACE_FLAGS_SYSTEM_CACHE_LINE_SIZE |
                                             PCI_TDISP_LOCK_INTERFACE_FLAGS_LOCK_MSIX;
    g_tdisp_interface_context.tdisp_rsp_caps.dev_addr_width = 48;
    g_tdisp_interface_context.tdisp_rsp_caps.num_req_this = 0;
    g_tdisp_interface_context.tdisp_rsp_caps.num_req_all = 0;

    g_tdisp_interface_context.tdi_state = PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED;

    return &g_tdisp_interface_context;
}

libtdisp_interface_context *libtdisp_get_interface_context (
    const pci_tdisp_interface_id_t *interface_id
    )
{
    if (libspdm_const_compare_mem (&g_tdisp_interface_context.interface_id,
                                   interface_id,
                                   sizeof(g_tdisp_interface_context.interface_id)) == 0) {
        return &g_tdisp_interface_context;
    } else {
        return NULL;
    }
}
