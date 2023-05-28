/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)

extern SOCKET m_socket;

extern void *m_spdm_context;

bool communicate_platform_data(SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id);
#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

libspdm_return_t pci_doe_process_session_message(void *spdm_context, uint32_t session_id);
libspdm_return_t mctp_process_session_message(void *spdm_context, uint32_t session_id);
libspdm_return_t do_certificate_provising_via_spdm(uint32_t* session_id);

libspdm_return_t do_app_session_via_spdm(uint32_t session_id)
{
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        status = pci_doe_process_session_message (m_spdm_context, session_id);
    }

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        status = mctp_process_session_message (m_spdm_context, session_id);
    }

    return status;
}

libspdm_return_t get_digest_cert_in_session(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;
    uint8_t slot_mask;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_context = m_spdm_context;
    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    if ((m_exe_session & EXE_SESSION_DIGEST) != 0) {
        status = libspdm_get_digest(spdm_context, session_id, &slot_mask, total_digest_buffer);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }
    if ((m_exe_session & EXE_SESSION_CERT) != 0) {
        if (m_use_slot_id != 0xFF) {
            status = libspdm_get_certificate_ex(
                spdm_context, session_id, m_use_slot_id, &cert_chain_size, cert_chain, NULL, 0);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
    }

    return status;
}

libspdm_return_t do_session_via_spdm(bool use_psk)
{
    void *spdm_context;
    libspdm_return_t status;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t response_size;
    bool result;
    uint32_t response;

    spdm_context = m_spdm_context;

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_start_session(spdm_context, use_psk,
                                   LIBSPDM_TEST_PSK_HINT_STRING,
                                   sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                   m_use_measurement_summary_hash_type,
                                   m_use_slot_id, m_session_policy, &session_id,
                                   &heartbeat_period, measurement_hash);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_start_session - %x\n", (uint32_t)status);
        return status;
    }

    if ((m_exe_session & EXE_SESSION_APP) != 0) {
        status = do_app_session_via_spdm(session_id);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("do_app_session_via_spdm - %x\n", (uint32_t)status);
            return status;
        }
    }

    if ((m_exe_session & EXE_SESSION_HEARTBEAT) != 0) {
        status = libspdm_heartbeat(spdm_context, session_id);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_heartbeat - %x\n", (uint32_t)status);
        }
    }

    if ((m_exe_session & EXE_SESSION_KEY_UPDATE) != 0) {
        switch (m_use_key_update_action) {
        case LIBSPDM_KEY_UPDATE_ACTION_REQUESTER:
            status =
                libspdm_key_update(spdm_context, session_id, true);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                printf("libspdm_key_update - %x\n",
                       (uint32_t)status);
            }
            break;

        case LIBSPDM_KEY_UPDATE_ACTION_MAX:
            status = libspdm_key_update(spdm_context, session_id,
                                        false);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
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
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
                status = libspdm_send_receive_encap_request(
                    spdm_context, &session_id);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    printf("libspdm_send_receive_encap_request - libspdm_key_update - %x\n",
                           (uint32_t)status);
                }
#endif
            }
            break;

        default:
            LIBSPDM_ASSERT(false);
            break;
        }
    }

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if ((m_exe_session & EXE_SESSION_MEAS) != 0) {
        status = do_measurement_via_spdm(&session_id);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("do_measurement_via_spdm - %x\n",
                   (uint32_t)status);
        }
    }
#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)
    status = get_digest_cert_in_session(&session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("get_digest_cert_in_session - %x\n",
               (uint32_t)status);
    }
#endif

    if (m_use_version >= SPDM_MESSAGE_VERSION_12) {
        status = do_certificate_provising_via_spdm(&session_id);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("do_certificate_provising_via_spdm - %x\n",
                   (uint32_t)status);
            return status;
        }
    }

    if ((m_exe_session & EXE_SESSION_NO_END) == 0) {
        status = libspdm_stop_session(spdm_context, session_id,
                                      m_end_session_attributes);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_stop_session - %x\n", (uint32_t)status);
            return status;
        }
    }

    return status;
}

/*
 * These function implements the request and response messages used for provisioning a device with certificate chains.
 * Provisioning of Slot 0 should be only done in a secure environment (such as a secure manufacturing environment)
 */
libspdm_return_t do_certificate_provising_via_spdm(uint32_t* session_id)
{
    void *spdm_context;

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP
    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE];
    size_t csr_len;
#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP
    void *cert_chain_to_set;
    size_t cert_chain_size_to_set;
    uint8_t slot_id;
    bool res;

    cert_chain_to_set = NULL;
    cert_chain_size_to_set = 0;
#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP*/

    libspdm_return_t status;
    spdm_context = m_spdm_context;

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP

    /*get csr*/
    csr_len = LIBSPDM_MAX_CSR_SIZE;
    libspdm_zero_mem(csr_form_get, sizeof(csr_form_get));
    if ((m_exe_connection & EXE_CONNECTION_GET_CSR) != 0) {
        status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr_form_get,
                                 &csr_len);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_get_csr - %x\n",
                   (uint32_t)status);
            return status;
        }
    }

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP
    res = libspdm_read_responder_public_certificate_chain(m_use_hash_algo,
                                                          m_use_asym_algo,
                                                          &cert_chain_to_set,
                                                          &cert_chain_size_to_set,
                                                          NULL, NULL);
    if (!res) {
        printf("set certificate :read_responder_public_certificate_chain fail!\n");
        free(cert_chain_to_set);
        return LIBSPDM_STATUS_INVALID_CERT;
    }

    /*set_certificate for slot_id:0 in secure environment*/
    if ((m_exe_connection & EXE_CONNECTION_SET_CERT) != 0) {
        slot_id = 0;
        status = libspdm_set_certificate(spdm_context, NULL, slot_id,
                                         cert_chain_to_set, cert_chain_size_to_set);

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_set_certificate - %x\n",
                   (uint32_t)status);
            free(cert_chain_to_set);
            return status;
        }

    }

    /*set_certificate for slot_id:1 in secure session*/
    if (session_id != NULL) {
        if ((m_exe_session & EXE_SESSION_SET_CERT) != 0) {
            if (m_other_slot_id != 0) {
                slot_id = m_other_slot_id;
                status = libspdm_set_certificate(spdm_context, session_id, slot_id,
                                                cert_chain_to_set, cert_chain_size_to_set);

                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    printf("libspdm_set_certificate - %x\n",
                        (uint32_t)status);
                }

                free(cert_chain_to_set);
                return status;
            }
        }
    }

    free(cert_chain_to_set);
#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP*/
    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*(LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)*/
