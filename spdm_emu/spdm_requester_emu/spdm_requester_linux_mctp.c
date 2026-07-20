/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

/**
 * Linux kernel AF_MCTP socket creation for the SPDM requester.
 *
 * This file is only compiled on Linux (CMake if(UNIX)) so it contains no
 * compile-time platform guards.
 **/

#include "spdm_requester_emu.h"
#include "spdm_emu_mctp_kernel.h"

#include <linux/mctp.h>
#include <errno.h>

/**
 * Create an AF_MCTP SOCK_DGRAM socket for the SPDM requester.
 *
 * The requester does NOT call bind().  When sendto() is issued with
 * MCTP_TAG_OWNER the kernel allocates a message tag and routes the
 * corresponding response back to this socket automatically.  Binding here
 * would compete with a concurrently running responder that has already
 * bound the same (network, MCTP_ADDR_ANY, type) tuple and cause EADDRINUSE.
 *
 * m_use_eid must be a valid unicast EID (1-254, per DSP0236 §8.2).
 **/
bool init_mctp_kernel_client(SOCKET *sock)
{
    if (m_use_eid == 0) {
        printf("MCTP_KERNEL transport requires a destination EID. "
               "Use --eid <1-254>.\n");
        return false;
    }

    SOCKET s = socket(AF_MCTP, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        printf("Create MCTP socket failed - %d\n", errno);
        return false;
    }

    /*
     * Register the kernel MCTP IO ops and reset any peer address state left
     * over from a previous session so write starts in the requester state.
     */
    spdm_emu_mctp_kernel_register_io_ops();

    printf("MCTP socket created (dst EID 0x%02x, net %u)\n",
           m_use_eid, m_use_net);
    *sock = s;
    return true;
}
