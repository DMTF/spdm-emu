/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

void *m_spdm_context;
#if LIBSPDM_FIPS_MODE
void *m_fips_selftest_context;
#endif /*LIBSPDM_FIPS_MODE*/
void *m_scratch_buffer;

extern uint32_t m_command;

extern SOCKET m_server_socket;

extern bool m_send_key_update;
extern bool m_send_get_endpoint_info;

/* Buffer for the Requester's certificate chain, passed to
 * libspdm_get_encap_request_get_certificate. It must outlive the handler call,
 * as libspdm accumulates the chain into it across several messages. */
static void *m_requester_cert_chain_buffer;
static void *m_requester_endpoint_info_buffer;

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
void spdm_server_session_state_callback(void *spdm_context,
                                        uint32_t session_id,
                                        libspdm_session_state_t session_state);

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
void spdm_server_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state);

libspdm_return_t spdm_get_response_vendor_defined_request(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response);

static libspdm_return_t spdm_encap_flow_handler(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request);

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t response_size, const void *response,
                                          uint64_t timeout)
{
    bool result;

    result = send_platform_data(m_server_socket, SOCKET_SPDM_COMMAND_NORMAL,
                                response, (uint32_t)response_size);
    if (!result) {
        EMU_ERR("send_platform_data Error - %x\n", socket_errno());
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *request_size,
                                             void **request,
                                             uint64_t timeout)
{
    bool result;

    assert (*request == m_send_receive_buffer);
    m_send_receive_buffer_size = sizeof(m_send_receive_buffer);
    result =
        receive_platform_data(m_server_socket, &m_command,
                              m_send_receive_buffer, &m_send_receive_buffer_size);
    if (!result) {
        EMU_ERR("receive_platform_data Error - %x\n", socket_errno());
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (m_command == SOCKET_SPDM_COMMAND_NORMAL ||
        m_command == SOCKET_SPDM_COMMAND_DECAP_TDISP) {

        /* Cache the message in case it is not for SPDM.*/

    } else {

        /* Cache the message*/

        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    *request = m_send_receive_buffer;
    *request_size = m_send_receive_buffer_size;

    return LIBSPDM_STATUS_SUCCESS;
}

void *spdm_server_init(void)
{
    void *spdm_context;
#if LIBSPDM_FIPS_MODE
    void * fips_selftest_context;
    void *fips_selftest_buffer;
    size_t fips_selftest_buffer_size;
#endif /*LIBSPDM_FIPS_MODE*/
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    spdm_version_number_t spdm_version;
    libspdm_return_t status;
    size_t scratch_buffer_size;
    uint32_t max_spdm_msg_size;

    EMU_LOG("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());

    m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (m_spdm_context == NULL) {
        return NULL;
    }
    spdm_context = m_spdm_context;
    libspdm_init_context(spdm_context);

#if LIBSPDM_FIPS_MODE
    m_fips_selftest_context = (void *)malloc(libspdm_get_fips_selftest_context_size());
    if (m_fips_selftest_context == NULL) {
        return NULL;
    }
    fips_selftest_context = m_fips_selftest_context;
    fips_selftest_buffer_size = libspdm_get_fips_selftest_buffer_size();
    fips_selftest_buffer = (void *)malloc(fips_selftest_buffer_size);
    if (fips_selftest_buffer == NULL) {
        return NULL;
    }
    libspdm_init_fips_selftest_context(fips_selftest_context,
                                       fips_selftest_buffer_size,
                                       fips_selftest_buffer);

    if (!libspdm_import_fips_selftest_context_to_spdm_context(
            spdm_context, fips_selftest_context,
            libspdm_get_fips_selftest_context_size())) {
        return NULL;
    }
#endif /*LIBSPDM_FIPS_MODE*/

    libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                    spdm_device_receive_message);

    if (m_use_slot_id == 0xFF) {
        m_use_responder_capability_flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP;
        m_use_responder_capability_flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    }
    if (m_use_capability_flags != 0) {
        m_use_responder_capability_flags = m_use_capability_flags;
    }
    max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
    if ((m_use_responder_capability_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP) == 0) {
        max_spdm_msg_size = LIBSPDM_RECEIVER_BUFFER_SIZE - LIBSPDM_TRANSPORT_ADDITIONAL_SIZE;
    }
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP
        || m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP_LINUX_KERNEL) {
        libspdm_register_transport_layer_func(
            spdm_context,
            max_spdm_msg_size,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            max_spdm_msg_size,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            max_spdm_msg_size,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_tcp_encode_message,
            libspdm_transport_tcp_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            max_spdm_msg_size,
            0,
            0,
            spdm_transport_none_encode_message,
            spdm_transport_none_decode_message);
    } else {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }
    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_SENDER_BUFFER_SIZE,
                                        LIBSPDM_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
    m_scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (m_scratch_buffer == NULL) {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);

    m_requester_cert_chain_buffer = (void *)malloc(SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
    if (m_requester_cert_chain_buffer == NULL)
    {
        return NULL;
    }

    m_requester_endpoint_info_buffer = (void *)malloc(LIBSPDM_MAX_ENDPOINT_INFO_LENGTH);
    if (m_requester_endpoint_info_buffer == NULL)
    {
        return NULL;
    }

    if (!libspdm_check_context(spdm_context))
    {
        return NULL;
    }

    if (m_load_state_file_name != NULL) {
        status = spdm_load_negotiated_state(spdm_context, false);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
    }

    if (m_use_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, sizeof(spdm_version));
    }

    if (m_use_secured_message_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = m_use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdm_context,
                         LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                         &parameter, &spdm_version,
                         sizeof(spdm_version));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    data8 = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));
    data32 = m_use_responder_capability_flags;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = m_support_measurement_spec;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = m_support_measurement_hash_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = m_support_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = m_support_hash_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = m_support_pqc_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_PQC_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = m_support_dhe_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = m_support_aead_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = m_support_req_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = m_support_key_schedule_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = m_support_other_params_support;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));
    data8 = m_support_mel_spec;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = m_support_req_pqc_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_PQC_ASYM_ALG, &parameter,
                     &data32, sizeof(data32));
    data32 = m_support_kem_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEM_ALG, &parameter,
                     &data32, sizeof(data32));

    data8 = m_support_pqc_first;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST, &parameter,
                     &data8, sizeof(data8));

    data8 = 0xF0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                     &data8, sizeof(data8));

    libspdm_register_get_response_func(
        spdm_context, spdm_get_response_vendor_defined_request);

    libspdm_register_session_state_callback_func(
        spdm_context, spdm_server_session_state_callback);
    libspdm_register_connection_state_callback_func(
        spdm_context, spdm_server_connection_state_callback);

    if (m_load_state_file_name != NULL) {
        /* Invoke callback to provision the rest*/
        spdm_server_connection_state_callback(
            spdm_context, LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    }

    libspdm_register_encap_flow_handler(spdm_context, spdm_encap_flow_handler);

    return m_spdm_context;
}

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
void spdm_server_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state)
{
    bool res;
    void *data;
    void *data1;
    void *data4;
    size_t data_size;
    size_t data1_size;
    size_t data4_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    libspdm_return_t status;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    uint8_t index;
    spdm_version_number_t spdm_version;
    bool requester_pub_key_needed;
    bool multi_key_conn_rsp;
    uint8_t populated_slot_count;

    switch (connection_state) {
    case LIBSPDM_CONNECTION_STATE_NOT_STARTED:

        /* clear perserved state*/

        if (m_save_state_file_name != NULL) {
            spdm_clear_negotiated_state(spdm_context);
        }
        break;

    case LIBSPDM_CONNECTION_STATE_AFTER_VERSION:
        if ((m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0) {
            /* GET_VERSION is done, handle special PSK use case*/
            status = spdm_provision_psk_version_only (spdm_context, false);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_ASSERT (false);
                return;
            }
            /* pass through to NEGOTIATED */
        } else {
            /* normal action - do nothing */
            break;
        }

    case LIBSPDM_CONNECTION_STATE_NEGOTIATED:

        if (m_use_version == 0) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            data_size = sizeof(spdm_version);
            libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                             &spdm_version, &data_size);
            m_use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
        }

        /* Provision new content*/

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                         &parameter, &data32, &data_size);
        m_use_measurement_hash_algo = data32;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO,
                         &parameter, &data32, &data_size);
        m_use_asym_algo = data32;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO,
                         &parameter, &data32, &data_size);
        m_use_hash_algo = data32;
        data_size = sizeof(data16);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                         &parameter, &data16, &data_size);
        m_use_req_asym_algo = data16;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_PQC_ASYM_ALGO,
                         &parameter, &data32, &data_size);
        m_use_pqc_asym_algo = data32;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_PQC_ASYM_ALG,
                         &parameter, &data32, &data_size);
        m_use_req_pqc_asym_algo = data32;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                        &data32, &data_size);

        if ((m_use_responder_capability_flags &
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) != 0) {
            m_use_slot_id = 0xFF;
        }
        if ((m_use_requester_capability_flags &
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0) {
            m_use_req_slot_id = 0xFF;
        }

        if (((m_use_requester_capability_flags &
              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG) != 0) ||
            (m_use_mut_auth == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED)) {
            requester_pub_key_needed = true;
        } else {
            requester_pub_key_needed = false;
        }

        EMU_LOG("slot_id - %x\n", m_use_slot_id);
        EMU_LOG("req_slot_id - %x\n", m_use_req_slot_id);

        if (m_use_slot_id == 0xFF) {
            if (m_use_asym_algo != 0) {
                res = libspdm_read_responder_public_key(m_use_asym_algo, &data, &data_size);
            }
            if (m_use_pqc_asym_algo != 0) {
                res = libspdm_read_responder_pqc_public_key(m_use_pqc_asym_algo, &data, &data_size);
            }
            if ((m_use_asym_algo != 0) || (m_use_pqc_asym_algo != 0)) {
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                                     &parameter, data, data_size);
                    /* Do not free it.*/
                }
            }
        } else {
            if (m_use_asym_algo != 0) {
                if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) == 0) {
                    res = libspdm_read_responder_public_certificate_chain(
                        m_use_hash_algo,
                        m_use_asym_algo,
                        &data, &data_size,
                        NULL, NULL);
                } else {
                    res = libspdm_read_responder_public_certificate_chain_alias_cert(
                        m_use_hash_algo,
                        m_use_asym_algo,
                        &data, &data_size,
                        NULL, NULL);
                }

                res = libspdm_read_responder_public_certificate_chain_per_slot(
                    1,
                    m_use_hash_algo,
                    m_use_asym_algo,
                    &data1, &data1_size,
                    NULL, NULL);

                /* slot 4 uses a different leaf key (multi-key example). */
                res = libspdm_read_responder_public_certificate_chain_per_slot(
                    4,
                    m_use_hash_algo,
                    m_use_asym_algo,
                    &data4, &data4_size,
                    NULL, NULL);
            }
            if (m_use_pqc_asym_algo != 0) {
                if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) == 0) {
                    res = libspdm_read_pqc_responder_public_certificate_chain(
                        m_use_hash_algo,
                        m_use_pqc_asym_algo,
                        &data, &data_size,
                        NULL, NULL);
                } else {
                    res = libspdm_read_pqc_responder_public_certificate_chain_alias_cert(
                        m_use_hash_algo,
                        m_use_pqc_asym_algo,
                        &data, &data_size,
                        NULL, NULL);
                }

                res = libspdm_read_pqc_responder_public_certificate_chain_per_slot(
                    1,
                    m_use_hash_algo,
                    m_use_pqc_asym_algo,
                    &data1, &data1_size,
                    NULL, NULL);

                /* slot 4 uses a different leaf key (multi-key example). */
                res = libspdm_read_pqc_responder_public_certificate_chain_per_slot(
                    4,
                    m_use_hash_algo,
                    m_use_pqc_asym_algo,
                    &data4, &data4_size,
                    NULL, NULL);
            }
            if ((m_use_asym_algo != 0) || (m_use_pqc_asym_algo != 0)) {
                if (res) {
                    /* Populate a NON-CONTIGUOUS set of slots. Slots 0 and 1 share the negotiated
                     * algorithm's (single) leaf key. Slot 4 carries a DIFFERENT leaf key (data4) to
                     * demonstrate multiple keys; it is provisioned ONLY in a multi-key connection.
                     * In a non-multi-key connection (e.g. SPDM 1.1/1.2, or 1.3+ without multi-key),
                     * the endpoint has a single key pair per algorithm (DSP0274), KeyPairID is
                     * forced to 0, and the responder signs with the default key - so slot 4's
                     * distinct key could not be authenticated and must not be offered.
                     *
                     * SlotIDs may be non-contiguous, but per DSP0274 KeyPairIDs are contiguous
                     * 1..TotalKeyPairs and each KeyPairID has one fixed algorithm. Each slot's
                     * KeyPairID is the REAL device-global id of the negotiated algorithm's key pair:
                     * slots 0/1 use that algorithm's primary key pair, slot 4 its secondary
                     * (resolved by libspdm_get_key_pair_id_by_slot). */
                    static const uint8_t populated_slot_id[] = { 0, 1, 4 };
                    void *slot_data[3];
                    size_t slot_data_size[3];
                    size_t slot_index;
                    size_t multi_key_data_size;

                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                    multi_key_data_size = sizeof(multi_key_conn_rsp);
                    multi_key_conn_rsp = false;
                    libspdm_get_data(spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                                     &multi_key_conn_rsp, &multi_key_data_size);
                    /* slot 4 (the distinct-key example) is provisioned only when this
                     * connection is multi-key; otherwise its cert chain data is empty,
                     * so a long-lived responder never carries slot 4 over from an
                     * earlier multi-key connection into a later non-multi-key one. */
                    slot_data[0] = data;
                    slot_data[1] = data1;
                    slot_data[2] = multi_key_conn_rsp ? data4 : NULL;
                    slot_data_size[0] = data_size;
                    slot_data_size[1] = data1_size;
                    slot_data_size[2] = multi_key_conn_rsp ? data4_size : 0;
                    populated_slot_count = (uint8_t)LIBSPDM_ARRAY_SIZE(populated_slot_id);

                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

                    for (slot_index = 0; slot_index < populated_slot_count;
                         slot_index++) {
                        parameter.additional_data[0] = populated_slot_id[slot_index];
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                         &parameter, slot_data[slot_index],
                                         slot_data_size[slot_index]);
                        /* real, algorithm-matched, contiguous KeyPairID for this slot. */
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
                        data8 = libspdm_get_key_pair_id_by_slot(
                            m_use_asym_algo, m_use_pqc_asym_algo, populated_slot_id[slot_index]);
#else
                        data8 = (uint8_t)(slot_index + 1);
#endif
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_KEY_PAIR_ID,
                                         &parameter, &data8, sizeof(data8));
                        data8 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_CERT_INFO,
                                         &parameter, &data8, sizeof(data8));
                        data16 = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
                                SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
                                SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
                                SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE;
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK,
                                         &parameter, &data16, sizeof(data16));
                    }
                    /* do not free it*/
                }
            }
        }

        if (m_use_req_slot_id == 0xFF) {
            if (m_use_req_asym_algo != 0) {
                res = libspdm_read_requester_public_key(m_use_req_asym_algo, &data, &data_size);
            }
            if (m_use_req_pqc_asym_algo != 0) {
                res = libspdm_read_requester_pqc_public_key(m_use_req_pqc_asym_algo, &data, &data_size);
            }
            if ((m_use_req_asym_algo != 0) || (m_use_req_pqc_asym_algo != 0)) {
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_PEER_PUBLIC_KEY,
                                     &parameter, data, data_size);
                    /* Do not free it.*/
                }
            }
        } else {
            if (m_use_req_asym_algo != 0) {
                res = libspdm_read_requester_root_public_certificate(
                    m_use_hash_algo, m_use_req_asym_algo, &data,
                    &data_size, &hash, &hash_size);
                if (requester_pub_key_needed) {
                    res = libspdm_read_requester_public_certificate_chain(
                        m_use_hash_algo, m_use_req_asym_algo,
                        &data1, &data1_size, NULL, NULL);
                }
            }
            if (m_use_req_pqc_asym_algo != 0) {
                res = libspdm_read_pqc_requester_root_public_certificate(
                    m_use_hash_algo, m_use_req_pqc_asym_algo, &data,
                    &data_size, &hash, &hash_size);
                if (requester_pub_key_needed) {
                    res = libspdm_read_pqc_requester_public_certificate_chain(
                        m_use_hash_algo, m_use_req_pqc_asym_algo,
                        &data1, &data1_size, NULL, NULL);
                }
            }
            if ((m_use_req_asym_algo != 0) || (m_use_req_pqc_asym_algo != 0)) {
                if (res) {
                    libspdm_x509_get_cert_from_cert_chain(
                        (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                        data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                        &root_cert, &root_cert_size);
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(
                        spdm_context,
                        LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                        &parameter, (void *)root_cert, root_cert_size);
                    /* Do not free it.*/
                    if (requester_pub_key_needed) {
                        libspdm_zero_mem(&parameter, sizeof(parameter));
                        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                        for (index = 0; index < m_use_slot_count; index++) {
                            parameter.additional_data[0] = index;
                            libspdm_set_data(spdm_context,
                                             LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                                             &parameter, data1, data1_size);
                            data8 = (uint8_t)(0xB0 + index);
                            libspdm_set_data(spdm_context,
                                             LIBSPDM_DATA_PEER_KEY_PAIR_ID,
                                             &parameter, &data8, sizeof(data8));
                            data8 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
                            libspdm_set_data(spdm_context,
                                             LIBSPDM_DATA_PEER_CERT_INFO,
                                             &parameter, &data8, sizeof(data8));
                            data16 = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
                                     SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
                                     SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
                                     SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE;
                            libspdm_set_data(spdm_context,
                                             LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK,
                                             &parameter, &data16, sizeof(data16));
                        }
                    }
                }
            }
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                         &data32, &data_size);

        if (((m_use_req_asym_algo != 0) || (m_use_req_pqc_asym_algo != 0)) &&
            ((data32 & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP) != 0)) {
            if (res) {
                if (m_use_req_slot_id == 0xFF) {
                    /* 0xFF slot is only allowed in */
                    m_use_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
                }
                g_key_exchange_start_mut_auth = m_use_mut_auth;
                g_key_exchange_req_slot_id = m_use_req_slot_id;

                g_start_basic_mut_auth = (m_use_basic_mut_auth == 1);
            }
        } else {
            /* Requester did not declare MUT_AUTH_CAP: do not offer mutual auth,
             * and clear any stale state left over from a prior connection. */
            g_key_exchange_start_mut_auth = 0;
            g_start_basic_mut_auth = false;
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        data_size = sizeof(multi_key_conn_rsp);
        multi_key_conn_rsp = false;
        libspdm_get_data(spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                         &multi_key_conn_rsp, &data_size);

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        /* Slots 0 and 1 are always populated. Slot 4 (the distinct-key multi-key example, a
         * non-contiguous SlotID; slots 2 and 3 stay empty) is only present in a multi-key
         * connection. */
        data8 = (1 << 0) | (1 << 1);
        if (multi_key_conn_rsp) {
            data8 |= (1 << 4);
        }
        libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, &parameter,
                         &data8, sizeof(data8));

        if (m_save_state_file_name != NULL) {
            spdm_save_negotiated_state(spdm_context, false);
        }

        break;

    default:
        break;
    }

    return;
}

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
void spdm_server_session_state_callback(void *spdm_context,
                                        uint32_t session_id,
                                        libspdm_session_state_t session_state)
{
    size_t data_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;

    switch (session_state) {
    case LIBSPDM_SESSION_STATE_NOT_STARTED:
        /* Session end*/

        if (m_save_state_file_name != NULL) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
            *(uint32_t *)parameter.additional_data = session_id;

            data_size = sizeof(data8);
            libspdm_get_data(spdm_context,
                             LIBSPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
                             &parameter, &data8, &data_size);
            if ((data8 &
                 SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR) !=
                0) {
                /* clear*/
                spdm_clear_negotiated_state(spdm_context);
            } else {
                /* preserve - already done in LIBSPDM_CONNECTION_STATE_NEGOTIATED.
                 * spdm_save_negotiated_state (spdm_context, false);*/
            }
        }
        break;

    case LIBSPDM_SESSION_STATE_HANDSHAKING:
        /* collect session policy*/
        if (m_use_version >= SPDM_MESSAGE_VERSION_12) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
            *(uint32_t *)parameter.additional_data = session_id;

            data8 = 0;
            data_size = sizeof(data8);
            libspdm_get_data(spdm_context,
                             LIBSPDM_DATA_SESSION_POLICY,
                             &parameter, &data8, &data_size);
            EMU_LOG("session policy - %x\n", data8);
        }
        break;

    case LIBSPDM_SESSION_STATE_ESTABLISHED:
        /* no action*/
        break;

    default:
        LIBSPDM_ASSERT(false);
        break;
    }
}

static libspdm_return_t spdm_encap_flow_handler(
    void *spdm_context,
    const uint32_t *session_id,
    libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code,
    uint8_t error_code,
    bool *terminate_flow,
    size_t *encap_request_size,
    void *encap_request)
{
    static uint8_t basic_mut_auth_counter = 0;
    static uint8_t sess_mut_auth_counter = 0;

    EMU_LOG("spdm_encap_flow_handler()\n");
    EMU_LOG("  session_id - ");
    if (session_id == NULL) {
        EMU_LOG("NULL\n");
    } else {
        EMU_LOG("0x%x\n", *session_id);
    }
    EMU_LOG("  encap_flow_type - %d\n", encap_flow_type);
    EMU_LOG("  last_request_code - 0x%x\n", last_request_code);
    EMU_LOG("  error_code - 0x%x\n", error_code);

    if (error_code != 0) {
        /* The Requester returned an encapsulated ERROR, so the flow ends here. Reset the
         * counters so that a later flow starts from the beginning. */
        EMU_LOG("  Requester returned encapsulated ERROR, terminating flow\n");
        basic_mut_auth_counter = 0;
        sess_mut_auth_counter = 0;
        *terminate_flow = true;
        *encap_request_size = 0;

        return LIBSPDM_STATUS_SUCCESS;
    }

    if (last_request_code == SPDM_GET_CERTIFICATE) {
        size_t cert_chain_size = 0;

        if (libspdm_get_encap_payload_size(spdm_context, session_id, &cert_chain_size) ==
            LIBSPDM_STATUS_SUCCESS) {
            EMU_LOG("  retrieved cert_chain_size - 0x%x\n", (uint32_t)cert_chain_size);
        }
    }

    if (last_request_code == SPDM_GET_ENDPOINT_INFO) {
        size_t endpoint_info_size = 0;

        if (libspdm_get_encap_payload_size(spdm_context, session_id, &endpoint_info_size) ==
            LIBSPDM_STATUS_SUCCESS) {
            EMU_LOG("  retrieved endpoint_info_size - 0x%x\n", (uint32_t)endpoint_info_size);
            EMU_LOG("  endpoint_info:");
            dump_data(m_requester_endpoint_info_buffer, endpoint_info_size);
            EMU_LOG("\n");
        }
    }

    *terminate_flow = false;

    switch (encap_flow_type) {
    case LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH:
        switch (basic_mut_auth_counter) {
        case 0:
            basic_mut_auth_counter++;

            return libspdm_get_encap_request_get_digests(
                spdm_context, session_id, encap_request_size, encap_request);
        case 1:
            basic_mut_auth_counter++;

            return libspdm_get_encap_request_get_certificate(
                spdm_context, session_id, 0, SPDM_MAX_CERTIFICATE_CHAIN_SIZE,
                m_requester_cert_chain_buffer, encap_request_size, encap_request);
        default:
            /* CHALLENGE is the last request of this flow. libspdm terminates the flow itself once
             * the Requester delivers CHALLENGE_AUTH, so this handler is not called again. */
            basic_mut_auth_counter = 0;

            return libspdm_get_encap_request_challenge(
                spdm_context, 0, NULL, encap_request_size, encap_request);
        }
    case LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH:
        switch (sess_mut_auth_counter) {
        case 0:
            sess_mut_auth_counter++;

            return libspdm_get_encap_request_get_digests(
                spdm_context, session_id, encap_request_size, encap_request);
        case 1:
            sess_mut_auth_counter++;

            return libspdm_get_encap_request_get_certificate(
                spdm_context, session_id, 0, SPDM_MAX_CERTIFICATE_CHAIN_SIZE,
                m_requester_cert_chain_buffer, encap_request_size, encap_request);
        default:
            /* The Requester's certificate chain has been retrieved, so end the flow. libspdm
             * designates m_use_req_slot_id in the final ENCAPSULATED_RESPONSE_ACK. */
            sess_mut_auth_counter = 0;
            break;
        }
        break;
    case LIBSPDM_ENCAP_FLOW_GENERAL:
        if (m_send_key_update) {
            m_send_key_update = false;

            return libspdm_get_encap_request_key_update(
                spdm_context, *session_id, SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY,
                encap_request_size, encap_request);
        } else if (m_send_get_endpoint_info) {
            uint8_t request_attributes = 0;
            libspdm_data_parameter_t parameter;
            uint32_t requester_flags;
            size_t data_size;

            m_send_get_endpoint_info = false;

            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            requester_flags = 0;
            data_size = sizeof(requester_flags);
            libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                             &requester_flags, &data_size);

            if ((requester_flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG) != 0) {
                request_attributes =
                    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
            }

            return libspdm_get_encap_request_get_endpoint_info(
                spdm_context, session_id,
                SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0,
                request_attributes, LIBSPDM_MAX_ENDPOINT_INFO_LENGTH,
                m_requester_endpoint_info_buffer, encap_request_size, encap_request);
        }
        break;
    default:
        break;
    }

    /* No encapsulated request to send, so end the flow. encap_request_size is still the size of
     * the buffer that libspdm offered, so it must be cleared. */
    *terminate_flow = true;
    *encap_request_size = 0;

    return LIBSPDM_STATUS_SUCCESS;
}
