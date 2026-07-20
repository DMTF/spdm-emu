/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

/**
 * Linux kernel AF_MCTP socket creation for the SPDM responder.
 *
 * This file is only compiled on Linux (CMake if(UNIX)) so it contains no
 * compile-time platform guards.
 **/

#include "spdm_responder_emu.h"
#include "spdm_emu_mctp_kernel.h"

#include <linux/mctp.h>
#include <errno.h>
#include <string.h>

/**
 * Create and bind an AF_MCTP SOCK_DGRAM socket for the SPDM responder.
 *
 * The socket is bound to (m_use_net, MCTP_ADDR_ANY, MCTP_MESSAGE_TYPE_SPDM)
 * so it receives all incoming SPDM messages regardless of the local EID.
 * Binding to MCTP_ADDR_ANY avoids requiring a specific EID to be assigned
 * to a local interface by the MCTP daemon.
 *
 * If m_use_net is MCTP_NET_ANY (0) the kernel selects the network
 * automatically when only one network is present.
 *
 * The port_number parameter is ignored (MCTP has no port concept); it is
 * accepted for signature compatibility with create_socket().
 **/
bool create_mctp_kernel_socket(uint16_t port_number, SOCKET *mctp_socket)
{
    (void)port_number;

    SOCKET s = socket(AF_MCTP, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        printf("Create MCTP socket failed - %d\n", errno);
        return false;
    }

    struct sockaddr_mctp addr = { 0 };
    addr.smctp_family       = AF_MCTP;
    addr.smctp_network      = m_use_net;
    addr.smctp_addr.s_addr  = MCTP_ADDR_ANY;
    addr.smctp_type         = MCTP_MESSAGE_TYPE_SPDM;

    int rc = bind(s, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == -1) {
        printf("MCTP bind failed - %s\n", strerror(errno));
        closesocket(s);
        return false;
    }

    /*
     * Register the kernel MCTP IO ops and reset any peer address state left
     * over from a previous session.
     */
    spdm_emu_mctp_kernel_register_io_ops();

    printf("MCTP responder socket bound (net %u, type 0x%02x)\n",
           m_use_net, MCTP_MESSAGE_TYPE_SPDM);
    *mctp_socket = s;
    return true;
}
