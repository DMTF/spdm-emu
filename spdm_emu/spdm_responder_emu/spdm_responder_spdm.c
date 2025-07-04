/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
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

/**
 * Encapsulate Get Endpoint Info Callback Function.
 *
 * @param spdm_context       A pointer to the SPDM context.
 * @param subcode            The subcode of the GET_ENDPOINT_INFO request.
 * @param param2             Bit [7:4]. Reserved.
 *                           Bit [3:0]. SlotID.
 * @param request_attributes The request attributes of the GET_ENDPOINT_INFO request.
 * @param endpoint_info_size The size in bytes of the endpoint_info buffer.
 * @param endpoint_info      A pointer to the buffer to store the endpoint information.
 */
libspdm_return_t spdm_get_endpoint_info_callback (
    void *spdm_context,
    uint8_t subcode,
    uint8_t param2,
    uint8_t request_attributes,
    uint32_t endpoint_info_size,
    const void *endpoint_info);

libspdm_return_t spdm_get_response_vendor_defined_request(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response);

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t response_size, const void *response,
                                          uint64_t timeout)
{
    bool result;

    result = send_platform_data(m_server_socket, SOCKET_SPDM_COMMAND_NORMAL,
                                response, (uint32_t)response_size);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
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
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (m_command == SOCKET_SPDM_COMMAND_NORMAL) {

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
#endif /*LIBSPDM_FIPS_MODE*/
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    spdm_version_number_t spdm_version;
    libspdm_return_t status;
    size_t scratch_buffer_size;
    void *requester_cert_chain_buffer;

    printf("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());

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
    libspdm_init_fips_selftest_context(fips_selftest_context);

    if (!libspdm_import_fips_selftest_context_to_spdm_context(
            spdm_context, fips_selftest_context,
            libspdm_get_fips_selftest_context_size())) {
        return NULL;
    }
#endif /*LIBSPDM_FIPS_MODE*/

    libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                    spdm_device_receive_message);

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_tcp_encode_message,
            libspdm_transport_tcp_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
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

    requester_cert_chain_buffer = (void *)malloc(SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
    if (requester_cert_chain_buffer == NULL)
    {
        return NULL;
    }
    libspdm_register_cert_chain_buffer(spdm_context, requester_cert_chain_buffer,
                                       SPDM_MAX_CERTIFICATE_CHAIN_SIZE);

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
    if (m_use_slot_id == 0xFF) {
        data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    }
    if (m_use_capability_flags != 0) {
        data32 = m_use_capability_flags;
        m_use_responder_capability_flags = m_use_capability_flags;
    }
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

    data8 = 0xF0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                     &data8, sizeof(data8));

    /*total key pair info number*/
    data8 = libspdm_read_total_key_pairs();
    libspdm_set_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS, &parameter,
                     &data8, sizeof(data8));

    libspdm_register_get_response_func(
        spdm_context, spdm_get_response_vendor_defined_request);

    libspdm_register_get_endpoint_info_callback_func(
        spdm_context, spdm_get_endpoint_info_callback);

    libspdm_register_session_state_callback_func(
        spdm_context, spdm_server_session_state_callback);
    libspdm_register_connection_state_callback_func(
        spdm_context, spdm_server_connection_state_callback);

    if (m_load_state_file_name != NULL) {
        /* Invoke callback to provision the rest*/
        spdm_server_connection_state_callback(
            spdm_context, LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    }

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
    size_t data_size;
    size_t data1_size;
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

        printf("slot_id - %x\n", m_use_slot_id);
        printf("req_slot_id - %x\n", m_use_req_slot_id);

        if (m_use_slot_id == 0xFF) {
            res = libspdm_read_responder_public_key(m_use_asym_algo, &data, &data_size);
            if (res) {
                libspdm_zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                                 &parameter, data, data_size);
                /* Do not free it.*/
            }
        } else {
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
            if (res) {
                libspdm_zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

                for (index = 0; index < m_use_slot_count; index++) {
                    parameter.additional_data[0] = index;
                    if (index == 1) {
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                         &parameter, data1, data1_size);
                    } else {
                        libspdm_set_data(spdm_context,
                                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                         &parameter, data, data_size);
                    }
                    data8 = (uint8_t)(0xA0 + index);
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

        if (m_use_req_slot_id == 0xFF) {
            if (m_use_req_asym_algo != 0) {
                res = libspdm_read_requester_public_key(m_use_req_asym_algo, &data, &data_size);
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
                libspdm_x509_get_cert_from_cert_chain(
                    (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                    data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                    &root_cert, &root_cert_size);
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(
                        spdm_context,
                        LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                        &parameter, (void *)root_cert, root_cert_size);
                    /* Do not free it.*/
                }
            }
        }

        if (m_use_req_asym_algo != 0) {
            if (res) {
                if (m_use_req_slot_id == 0xFF) {
                    /* 0xFF slot is only allowed in */
                    m_use_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
                }
                data8 = m_use_mut_auth;
                parameter.additional_data[0] =
                    m_use_req_slot_id; /* req_slot_id;*/
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_MUT_AUTH_REQUESTED, &parameter,
                                 &data8, sizeof(data8));

                data8 = m_use_basic_mut_auth;
                parameter.additional_data[0] =
                    m_use_req_slot_id; /* req_slot_id;*/
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
                                 &parameter, &data8, sizeof(data8));
            }
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        data8 = 0;
        for (index = 0; index < m_use_slot_count; index++) {
            data8 |= (1 << index);
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
            printf("session policy - %x\n", data8);
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

libspdm_return_t spdm_get_endpoint_info_callback (
    void *spdm_context,
    uint8_t subcode,
    uint8_t param2,
    uint8_t request_attributes,
    uint32_t endpoint_info_size,
    const void *endpoint_info)
{
    printf("spdm_get_endpoint_info_callback\n");
    printf("  subcode - 0x%x\n", subcode);
    printf("  param2 - 0x%x\n", param2);
    printf("  request_attributes - 0x%x\n", request_attributes);
    printf("  endpoint_info_size - 0x%x\n", endpoint_info_size);
    printf("  endpoint_info:");
    dump_data(endpoint_info, endpoint_info_size);
    printf("\n");

    return LIBSPDM_STATUS_SUCCESS;
}