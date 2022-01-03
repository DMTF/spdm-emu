/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)

extern SOCKET m_socket;

extern void *m_spdm_context;

boolean communicate_platform_data(IN SOCKET socket, IN uint32_t command,
                  IN uint8_t *send_buffer, IN uintn bytes_to_send,
                  OUT uint32_t *response,
                  IN OUT uintn *bytes_to_receive,
                  OUT uint8_t *receive_buffer);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
return_status do_measurement_via_spdm(IN uint32_t *session_id);
#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

return_status pci_doe_process_session_message(IN void *spdm_context, IN uint32_t session_id);
return_status mctp_process_session_message(IN void *spdm_context, IN uint32_t session_id);

return_status do_app_session_via_spdm(IN uint32_t session_id)
{
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        pci_doe_process_session_message (m_spdm_context, session_id);
    }

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        mctp_process_session_message (m_spdm_context, session_id);
    }

    return RETURN_SUCCESS;
}

return_status do_session_via_spdm(IN boolean use_psk)
{
    void *spdm_context;
    return_status status;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn response_size;
    boolean result;
    uint32_t response;

    spdm_context = m_spdm_context;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_start_session(spdm_context, use_psk,
                    m_use_measurement_summary_hash_type,
                    m_use_slot_id, m_session_policy, &session_id,
                    &heartbeat_period, measurement_hash);
    if (RETURN_ERROR(status)) {
        printf("libspdm_start_session - %x\n", (uint32_t)status);
        return status;
    }

    do_app_session_via_spdm(session_id);

    if ((m_exe_session & EXE_SESSION_HEARTBEAT) != 0) {
        status = libspdm_heartbeat(spdm_context, session_id);
        if (RETURN_ERROR(status)) {
            printf("libspdm_heartbeat - %x\n", (uint32_t)status);
        }
    }

    if ((m_exe_session & EXE_SESSION_KEY_UPDATE) != 0) {
        switch (m_use_key_update_action) {
        case LIBSPDM_KEY_UPDATE_ACTION_REQUESTER:
            status =
                libspdm_key_update(spdm_context, session_id, TRUE);
            if (RETURN_ERROR(status)) {
                printf("libspdm_key_update - %x\n",
                       (uint32_t)status);
            }
            break;

        case LIBSPDM_KEY_UPDATE_ACTION_MAX:
            status = libspdm_key_update(spdm_context, session_id,
                         FALSE);
            if (RETURN_ERROR(status)) {
                printf("libspdm_key_update - %x\n",
                       (uint32_t)status);
            }
            break;

        case LIBSPDM_KEY_UPDATE_ACTION_RESPONDER:
            response_size = 0;
            result = communicate_platform_data(
                m_socket,
                SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL,
                0, &response, &response_size, NULL);
            if (!result) {
                printf("communicate_platform_data - SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE fail\n");
            } else {
                status = libspdm_send_receive_encap_request(
                    spdm_context, &session_id);
                if (RETURN_ERROR(status)) {
                    printf("libspdm_send_receive_encap_request - libspdm_key_update - %x\n",
                           (uint32_t)status);
                }
            }
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if ((m_exe_session & EXE_SESSION_MEAS) != 0) {
        status = do_measurement_via_spdm(&session_id);
        if (RETURN_ERROR(status)) {
            printf("do_measurement_via_spdm - %x\n",
                   (uint32_t)status);
        }
    }
#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    if ((m_exe_session & EXE_SESSION_NO_END) == 0) {
        status = libspdm_stop_session(spdm_context, session_id,
                       m_end_session_attributes);
        if (RETURN_ERROR(status)) {
            printf("libspdm_stop_session - %x\n", (uint32_t)status);
            return status;
        }
    }

    return status;
}

#endif /*(LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)*/
