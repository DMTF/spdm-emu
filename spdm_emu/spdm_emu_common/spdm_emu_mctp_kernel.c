/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

/**
 * Linux kernel AF_MCTP socket IO implementation.
 *
 * This file is only compiled on Linux (CMake if(UNIX)).  It contains no
 * compile-time platform guards — the CMake condition is the guard.
 *
 * It registers a spdm_emu_io_ops_t vtable (mctp_kernel_io_ops) into
 * command.c's dispatch table.  The vtable replaces the send/recv/framing
 * logic that would otherwise be scattered through command.c as
 * #ifndef _MSC_VER / MCTP_LINUX_KERNEL branches.
 **/

#include "spdm_emu.h"
#include "spdm_emu_mctp_kernel.h"

#include <linux/mctp.h>
#include <errno.h>
#include <string.h>

/*
 * Peer address captured by the most-recent recvfrom() call.
 *
 * DSP0236 §8.17: a requester sets MCTP_TAG_OWNER in outgoing messages and
 * the kernel allocates a tag, routing the response back to the same socket.
 * A responder receives MCTP_TAG_OWNER=1 and must reply with the same tag
 * value but MCTP_TAG_OWNER=0.  We detect which role we are from whether the
 * last received message carried MCTP_TAG_OWNER.
 */
static struct sockaddr_mctp m_mctp_recv_addr;
static bool m_mctp_recv_addr_valid = false;

/* ── Receive operations ──────────────────────────────────────────────────── */

static bool mctp_kernel_recv_command(SOCKET socket, uint32_t *command)
{
    (void)socket;
    /*
     * The Linux kernel MCTP socket carries no out-of-band command framing.
     * Synthesise SOCKET_SPDM_COMMAND_NORMAL so the responder dispatch loop
     * processes each incoming datagram as a normal SPDM message.
     */
    *command = SOCKET_SPDM_COMMAND_NORMAL;
    return true;
}

static bool mctp_kernel_recv_transport_type(SOCKET socket,
                                             uint32_t *transport_type)
{
    (void)socket;
    *transport_type = SOCKET_TRANSPORT_TYPE_MCTP_LINUX_KERNEL;
    return true;
}

static bool mctp_kernel_recv_payload(SOCKET socket, uint8_t *buffer,
                                      uint32_t *bytes_received,
                                      uint32_t max_buffer_length)
{
    struct sockaddr_mctp addr;
    socklen_t addrlen = sizeof(addr);
    int32_t rc;

    if (max_buffer_length < 2) {
        EMU_ERR("MCTP recv: buffer too small\n");
        return false;
    }

    /*
     * The kernel delivers one complete MCTP message per recvfrom() and does
     * NOT include the message type byte in the payload (it is carried in
     * sockaddr_mctp.smctp_type).  libspdm's MCTP transport layer expects
     * buffer[0] to be the IC+MessageType byte (0x05 for SPDM), so we
     * receive into buffer+1 and prepend it ourselves.
     */
    rc = recvfrom(socket, (char *)(buffer + 1), max_buffer_length - 1, 0,
                  (struct sockaddr *)&addr, &addrlen);
    if (rc < 0) {
        m_mctp_recv_addr_valid = false;
        EMU_ERR("MCTP recvfrom error: %s\n", strerror(errno));
        return false;
    }
    if (rc == 0) {
        /* Edge case: empty datagram — peer address is not meaningful. */
        m_mctp_recv_addr_valid = false;
        EMU_ERR("MCTP recvfrom: empty datagram\n");
        return false;
    }

    m_mctp_recv_addr       = addr;
    m_mctp_recv_addr_valid = true;

    buffer[0]      = MCTP_MESSAGE_TYPE_SPDM;
    *bytes_received = (uint32_t)rc + 1;

    EMU_LOG("Platform port Receive buffer (MCTP kernel):\n    ");
    dump_data(buffer, *bytes_received);
    EMU_LOG("\n");
    return true;
}

/* ── Send operations ─────────────────────────────────────────────────────── */

static bool mctp_kernel_send_payload(SOCKET socket, uint32_t command,
                                      const uint8_t *buffer,
                                      uint32_t bytes_to_send)
{
    (void)command;

    if (bytes_to_send == 0) {
        EMU_ERR("MCTP send: zero-length buffer\n");
        return false;
    }

    /*
     * Capture the role once before the send loop so all iterations use the
     * same peer address.  Evaluating m_mctp_recv_addr_valid inside the loop
     * could give inconsistent results if the flag is cleared mid-loop.
     */
    bool is_responder_reply = (m_mctp_recv_addr_valid &&
                               (m_mctp_recv_addr.smctp_tag & MCTP_TAG_OWNER));

    struct sockaddr_mctp addr = { 0 };
    addr.smctp_family = AF_MCTP;
    addr.smctp_type   = MCTP_MESSAGE_TYPE_SPDM;

    if (is_responder_reply) {
        /*
         * Reply to a request: clear MCTP_TAG_OWNER, keep the same network,
         * source EID, and tag value (DSP0236 §8.17).
         */
        addr.smctp_network      = m_mctp_recv_addr.smctp_network;
        addr.smctp_addr.s_addr  = m_mctp_recv_addr.smctp_addr.s_addr;
        addr.smctp_tag          = m_mctp_recv_addr.smctp_tag & MCTP_TAG_MASK;
    } else {
        /*
         * New request from the requester: set MCTP_TAG_OWNER so the kernel
         * allocates a tag and routes the response back to this socket.
         */
        addr.smctp_network      = m_use_net;
        addr.smctp_addr.s_addr  = m_use_eid;
        addr.smctp_tag          = MCTP_TAG_OWNER;
    }

    /*
     * buffer[0] is the IC+MessageType byte added by the libspdm MCTP
     * transport layer.  The kernel takes the type from smctp_type, so we
     * strip it before handing the payload to the kernel.  A 1-byte buffer
     * (type byte only, empty SPDM body) yields a 0-byte sendto, which is
     * valid for session control messages.
     */
    EMU_LOG("Platform port Transmit buffer (MCTP kernel):\n    ");
    dump_data(buffer, bytes_to_send);
    EMU_LOG("\n");

    const uint8_t *payload     = buffer + 1;
    uint32_t       payload_len = bytes_to_send - 1;
    uint32_t       number_sent = 0;

    while (number_sent < payload_len) {
        int32_t result = sendto(socket,
                                (const char *)(payload + number_sent),
                                payload_len - number_sent, 0,
                                (const struct sockaddr *)&addr, sizeof(addr));
        if (result == -1) {
            /* Edge case: send failure — invalidate stale peer address. */
            if (is_responder_reply)
                m_mctp_recv_addr_valid = false;
            EMU_ERR("MCTP sendto error - 0x%x\n", socket_errno());
            return false;
        }
        number_sent += (uint32_t)result;
    }

    /*
     * Edge case: reply sent successfully.  The MCTP tag is now consumed by
     * the kernel; reset the flag so the next send does not reuse this peer
     * address before a fresh recvfrom() delivers the next request.
     */
    if (is_responder_reply)
        m_mctp_recv_addr_valid = false;

    return true;
}

/* ── Vtable and registration ─────────────────────────────────────────────── */

static const spdm_emu_io_ops_t mctp_kernel_io_ops = {
    mctp_kernel_recv_command,
    mctp_kernel_recv_transport_type,
    mctp_kernel_recv_payload,
    mctp_kernel_send_payload,
};

void spdm_emu_mctp_kernel_register_io_ops(void)
{
    /*
     * Reset peer address so the first send starts in the requester state
     * rather than reusing leftover state from a previous session.
     */
    m_mctp_recv_addr_valid = false;
    spdm_emu_io_ops_register(&mctp_kernel_io_ops);
}
