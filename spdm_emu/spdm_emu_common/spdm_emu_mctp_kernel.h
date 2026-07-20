/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_EMU_MCTP_KERNEL_H__
#define __SPDM_EMU_MCTP_KERNEL_H__

/**
 * Register the Linux kernel AF_MCTP IO ops and reset the peer address state.
 *
 * Call once each time an AF_MCTP socket is opened — from
 * init_mctp_kernel_client() (requester) and create_mctp_kernel_socket()
 * (responder) — before any send/receive operation.
 *
 * On non-Linux platforms this is a no-op inline stub so callers need no
 * compile-time guards.
 */
#ifdef __linux__
void spdm_emu_mctp_kernel_register_io_ops(void);
#else
static inline void spdm_emu_mctp_kernel_register_io_ops(void) {}
#endif

#endif /* __SPDM_EMU_MCTP_KERNEL_H__ */
