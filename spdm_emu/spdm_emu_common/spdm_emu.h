/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
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
extern uint8_t m_use_version;
extern uint8_t m_use_secured_message_version;
extern uint32_t m_use_requester_capability_flags;
extern uint32_t m_use_responder_capability_flags;
extern uint32_t m_use_capability_flags;

extern uint8_t m_use_basic_mut_auth;
extern uint8_t m_use_mut_auth;
extern uint8_t m_use_measurement_summary_hash_type;
extern uint8_t m_use_measurement_operation;
extern uint8_t m_use_measurement_attribute;
extern uint8_t m_use_slot_id;
extern uint8_t m_use_slot_count;

#define ENCAP_KEY_UPDATE 0x8000
extern libspdm_key_update_action_t m_use_key_update_action;

extern uint32_t m_use_hash_algo;
extern uint32_t m_use_measurement_hash_algo;
extern uint32_t m_use_asym_algo;
extern uint16_t m_use_req_asym_algo;

extern uint8_t m_support_measurement_spec;
extern uint32_t m_support_measurement_hash_algo;
extern uint32_t m_support_hash_algo;
extern uint32_t m_support_asym_algo;
extern uint16_t m_support_req_asym_algo;
extern uint16_t m_support_dhe_algo;
extern uint16_t m_support_aead_algo;
extern uint16_t m_support_key_schedule_algo;
extern uint8_t m_support_other_params_support;

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
extern uint32_t m_exe_connection;

#define EXE_SESSION_KEY_EX 0x1
#define EXE_SESSION_PSK 0x2
#define EXE_SESSION_NO_END 0x4
#define EXE_SESSION_KEY_UPDATE 0x8
#define EXE_SESSION_HEARTBEAT 0x10
#define EXE_SESSION_MEAS 0x20
extern uint32_t m_exe_session;

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

void dump_data(const uint8_t *buffer, size_t buffer_size);

void dump_hex(const uint8_t *buffer, size_t buffer_size);

bool send_platform_data(SOCKET socket, uint32_t command,
                        const uint8_t *send_buffer, size_t bytes_to_send);

bool receive_platform_data(SOCKET socket, uint32_t *command,
                           uint8_t *receive_buffer,
                           size_t *bytes_to_receive);


return_status spdm_device_acquire_sender_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr);

return_status spdm_device_acquire_receiver_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr);

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool write_output_file(const char *file_name, const void *file_data,
                       size_t file_size);

bool open_pcap_packet_file(const char *pcap_file_name);

void close_pcap_packet_file(void);

void append_pcap_packet_data(const void *header, size_t header_size,
                             const void *data, size_t size);

void process_args(char *program_name, int argc, char *argv[]);

/* expose it because the responder/requester may use it to send/receive other message such as DOE discovery */
extern uint8_t m_send_receive_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
extern size_t m_send_receive_buffer_size;

#endif
