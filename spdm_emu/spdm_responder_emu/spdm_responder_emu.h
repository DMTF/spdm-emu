/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RESPONDER_TEST_H__
#define __SPDM_RESPONDER_TEST_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm_tcp_binding.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_none_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/spdm_transport_tcp_lib.h"
#include "library/mctp_responder_lib.h"
#include "library/pci_doe_responder_lib.h"
#include "library/pci_ide_km_responder_lib.h"
#include "library/pci_tdisp_responder_lib.h"
#include "library/cxl_ide_km_responder_lib.h"
#include "library/cxl_tsp_responder_lib.h"

#include "os_include.h"
#include <stdio.h>
#include "spdm_emu.h"

/**
 * Create and bind an AF_MCTP SOCK_DGRAM socket for the SPDM responder (Linux
 * kernel MCTP stack).  See spdm_responder_linux_mctp.c for details.
 *
 * On non-Linux platforms this is a stub that reports the transport is
 * unsupported, so call sites need no compile-time guard.
 */
#ifdef __linux__
bool create_mctp_kernel_socket(uint16_t port_number, SOCKET *mctp_socket);
#else
static inline bool create_mctp_kernel_socket(uint16_t port_number, SOCKET *mctp_socket)
{
    (void)port_number;
    (void)mctp_socket;
    printf("MCTP_KERNEL transport is only supported on Linux.\n");
    return false;
}
#endif

#endif
