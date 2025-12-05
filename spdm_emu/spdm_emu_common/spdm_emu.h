/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_TEST_H__
#define __SPDM_TEST_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "spdm_device_secret_lib_internal.h"

#include "os_include.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "assert.h"
#include "time.h"
#include "command.h"
#include "nv_storage.h"

extern uint32_t m_use_transport_layer;
extern uint32_t m_use_tcp_role_inquiry;
extern uint8_t m_use_version;
extern uint8_t m_use_secured_message_version;
extern uint32_t m_use_requester_capability_flags;
extern uint32_t m_use_responder_capability_flags;
extern uint32_t m_use_capability_flags;
extern uint32_t m_use_peer_capability_flags;

extern uint8_t m_use_basic_mut_auth;
extern uint8_t m_use_mut_auth;
extern uint8_t m_use_measurement_summary_hash_type;
extern uint8_t m_use_measurement_operation;
extern uint8_t m_use_measurement_attribute;
extern uint8_t m_use_slot_id;
extern uint8_t m_use_slot_count;
extern uint8_t m_use_req_slot_id;
extern bool g_private_key_mode;

#define ENCAP_KEY_UPDATE 0x8000
extern libspdm_key_update_action_t m_use_key_update_action;

extern uint32_t m_use_hash_algo;
extern uint32_t m_use_measurement_hash_algo;
extern uint32_t m_use_asym_algo;
extern uint16_t m_use_req_asym_algo;
extern uint32_t m_use_pqc_asym_algo;
extern uint32_t m_use_req_pqc_asym_algo;

extern uint8_t m_support_measurement_spec;
extern uint8_t m_support_mel_spec;
extern uint32_t m_support_measurement_hash_algo;
extern uint32_t m_support_hash_algo;
extern uint32_t m_support_asym_algo;
extern uint16_t m_support_req_asym_algo;
extern uint16_t m_support_dhe_algo;
extern uint16_t m_support_aead_algo;
extern uint16_t m_support_key_schedule_algo;
extern uint8_t m_support_other_params_support;
extern uint32_t m_support_pqc_asym_algo;
extern uint32_t m_support_req_pqc_asym_algo;
extern uint32_t m_support_kem_algo;
extern bool m_support_pqc_first;

extern uint8_t m_session_policy;
extern uint8_t m_end_session_attributes;

extern char *m_load_state_file_name;
extern char *m_save_state_file_name;

#define EXE_MODE_SHUTDOWN 0
#define EXE_MODE_CONTINUE 1
extern uint32_t m_exe_mode;

#define EXE_CONNECTION_VERSION_ONLY 0x1
#define EXE_CONNECTION_DIGEST 0x2
#define EXE_CONNECTION_CERT 0x4
#define EXE_CONNECTION_CHAL 0x8
#define EXE_CONNECTION_MEAS 0x10
#define EXE_CONNECTION_SET_CERT 0x20
#define EXE_CONNECTION_GET_CSR 0x40
#define EXE_CONNECTION_MEL 0x80
#define EXE_CONNECTION_GET_KEY_PAIR_INFO 0x100
#define EXE_CONNECTION_SET_KEY_PAIR_INFO 0x200
#define EXE_CONNECTION_EP_INFO 0x400
extern uint32_t m_exe_connection;

#define EXE_SESSION_KEY_EX 0x1
#define EXE_SESSION_PSK 0x2
#define EXE_SESSION_NO_END 0x4
#define EXE_SESSION_KEY_UPDATE 0x8
#define EXE_SESSION_HEARTBEAT 0x10
#define EXE_SESSION_MEAS 0x20
#define EXE_SESSION_SET_CERT 0x40
#define EXE_SESSION_GET_CSR 0x80
#define EXE_SESSION_DIGEST 0x100
#define EXE_SESSION_CERT 0x200
#define EXE_SESSION_APP 0x400
#define EXE_SESSION_MEL 0x800
#define EXE_SESSION_GET_KEY_PAIR_INFO 0x1000
#define EXE_SESSION_SET_KEY_PAIR_INFO 0x2000
#define EXE_SESSION_EP_INFO 0x4000
extern uint32_t m_exe_session;

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

void dump_data(const uint8_t *buffer, size_t buffer_size);

void dump_hex(const uint8_t *buffer, size_t buffer_size);

bool send_platform_data(SOCKET socket, uint32_t command,
                        const uint8_t *send_buffer, size_t bytes_to_send);

bool receive_platform_data(SOCKET socket, uint32_t *command,
                           uint8_t *receive_buffer,
                           size_t *bytes_to_receive);


libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr);

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);

bool open_pcap_packet_file(const char *pcap_file_name);

void close_pcap_packet_file(void);

void append_pcap_packet_data(const void *header, size_t header_size,
                             const void *data, size_t size);

void process_args(char *program_name, int argc, char *argv[]);

bool create_socket(uint16_t port_number, SOCKET *listen_socket);

bool init_client(SOCKET *sock, uint16_t port);

bool read_bytes(const SOCKET socket, uint8_t *buffer,
                uint32_t number_of_bytes);

bool write_bytes(const SOCKET socket, const uint8_t *buffer,
                 uint32_t number_of_bytes);

#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64

/* define common LIBSPDM_TRANSPORT_ADDITIONAL_SIZE. It should be the biggest one. */
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
    (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_NONE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in NONE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_TCP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in TCP
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_PCI_DOE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in PCI_DOE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_MCTP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in MCTP
#endif

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

// chunk disable.
#define LIBSPDM_MAX_SPDM_MSG_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
/* MLDSA - 0x8000, SLHDSA - 0x28000 */
#if ((LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT))
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x28000
#elif ((LIBSPDM_ML_DSA_44_SUPPORT) || \
    (LIBSPDM_ML_DSA_65_SUPPORT) || \
    (LIBSPDM_ML_DSA_87_SUPPORT))
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x8000
#else
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif
#endif

/* expose it because the responder/requester may use it to send/receive other message such as DOE discovery */
extern uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
extern size_t m_send_receive_buffer_size;

#ifndef LIBSPDM_MAX_CSR_SIZE
#define LIBSPDM_MAX_CSR_SIZE 0xffff
#endif

#ifndef LIBSPDM_MAX_ENDPOINT_INFO_LENGTH
#define LIBSPDM_MAX_ENDPOINT_INFO_LENGTH 1024
#endif

static inline bool libspdm_onehot0(uint32_t mask)
{
    return !mask || !(mask & (mask - 1));
}

#endif
