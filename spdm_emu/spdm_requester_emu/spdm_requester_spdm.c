/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

void *m_spdm_context;
void *m_scratch_buffer;
SOCKET m_socket;

bool communicate_platform_data(SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer)
{
    bool result;

    result =
        send_platform_data(socket, command, send_buffer, bytes_to_send);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }

    result = receive_platform_data(socket, response, receive_buffer,
                                   bytes_to_receive);
    if (!result) {
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }
    return result;
}

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                       size_t request_size, const void *request,
                                       uint64_t timeout)
{
    bool result;

    result = send_platform_data(m_socket, SOCKET_SPDM_COMMAND_NORMAL,
                                request, (uint32_t)request_size);
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
                                          size_t *response_size,
                                          void **response,
                                          uint64_t timeout)
{
    bool result;
    uint32_t command;

    result = receive_platform_data(m_socket, &command, *response,
                                   response_size);
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
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Send and receive an DOE message
 *
 * @param request                       the PCI DOE request message, start from pci_doe_data_object_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PCI DOE response message, start from pci_doe_data_object_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The request is sent and response is received.
 * @return ERROR                        The response is not received correctly.
 **/
libspdm_return_t pci_doe_send_receive_data(const void *pci_doe_context,
                                           size_t request_size, const void *request,
                                           size_t *response_size, void *response)
{
    bool result;
    uint32_t response_code;

    result = communicate_platform_data(
        m_socket, SOCKET_SPDM_COMMAND_NORMAL,
        request, request_size,
        &response_code, response_size,
        response);
    if (!result) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

void *spdm_client_init(void)
{
    void *spdm_context;
    uint8_t index;
    libspdm_return_t status;
    bool res;
    void *data;
    void *data1;
    size_t data_size;
    size_t data1_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    void *hash;
    void *hash1;
    size_t hash_size;
    size_t hash1_size;
    const uint8_t *root_cert;
    const uint8_t *root_cert1;
    size_t root_cert_size;
    size_t root_cert1_size;
    spdm_version_number_t spdm_version;
    size_t scratch_buffer_size;
    uint32_t requester_capabilities_flag;
    uint32_t responder_capabilities_flag;

    printf("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());

    m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (m_spdm_context == NULL) {
        return NULL;
    }
    spdm_context = m_spdm_context;
    libspdm_init_context(spdm_context);
    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
    m_scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (m_scratch_buffer == NULL) {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }

    libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                    spdm_device_receive_message);
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_context, libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message,
            libspdm_transport_mctp_get_header_size);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context, libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message,
            libspdm_transport_pci_doe_get_header_size);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
        libspdm_register_transport_layer_func(
            spdm_context, spdm_transport_none_encode_message,
            spdm_transport_none_decode_message,
            spdm_transport_none_get_header_size);
    } else {
        return NULL;
    }
    libspdm_register_device_buffer_func(spdm_context,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);

    if (m_load_state_file_name != NULL) {
        status = spdm_load_negotiated_state(spdm_context, true);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
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
    data32 = m_use_requester_capability_flags;
    if (m_use_capability_flags != 0) {
        data32 = m_use_capability_flags;
        m_use_requester_capability_flags = m_use_capability_flags;
    }
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = m_support_measurement_spec;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
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

    if (m_load_state_file_name == NULL) {
        /* Skip if state is loaded*/
        status = libspdm_init_connection(
            spdm_context,
            (m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_init_connection - 0x%x\n", (uint32_t)status);
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
        if ((m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0) {
            /* GET_VERSION is done, handle special PSK use case*/
            status = spdm_provision_psk_version_only (spdm_context, true);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return NULL;
            }
        }
    }

    if (m_use_version == 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        data_size = sizeof(spdm_version);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, &data_size);
        m_use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
    }

    /*get requester_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    requester_capabilities_flag = data32;

    /*get responder_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    responder_capabilities_flag = data32;

    /*change m_exe_connection and m_exe_session base on responder/requester supported capabilities*/
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP & responder_capabilities_flag) == 0) {
        m_exe_connection &= ~EXE_CONNECTION_DIGEST;
        m_exe_connection &= ~EXE_CONNECTION_CERT;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP & responder_capabilities_flag) == 0) {
        m_exe_connection &= ~EXE_CONNECTION_CHAL;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP & responder_capabilities_flag) == 0) {
        m_exe_connection &= ~EXE_CONNECTION_MEAS;
        m_exe_session &= ~EXE_SESSION_MEAS;
    }

    if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP & requester_capabilities_flag) == 0) ||
        ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP & responder_capabilities_flag) == 0)) {
        m_exe_session &= ~EXE_SESSION_KEY_EX;
    }
    if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP & requester_capabilities_flag) == 0) ||
        ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP & responder_capabilities_flag) == 0)) {
        m_exe_session &= ~EXE_SESSION_PSK;
    }
    if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP & requester_capabilities_flag) == 0) ||
        ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP & responder_capabilities_flag) == 0)) {
        m_exe_session &= ~EXE_SESSION_KEY_UPDATE;
    }
    if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP & requester_capabilities_flag) == 0) ||
        ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP & responder_capabilities_flag) == 0)) {
        m_exe_session &= ~EXE_SESSION_HEARTBEAT;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP & responder_capabilities_flag) == 0) {
        m_exe_session &= ~EXE_SESSION_SET_CERT;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP & responder_capabilities_flag) == 0) {
        m_exe_session &= ~EXE_SESSION_GET_CSR;
    }

    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
                     &data32, &data_size);
    LIBSPDM_ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &data32, &data_size);
    m_use_measurement_hash_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, &data_size);
    m_use_asym_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, &data_size);
    m_use_hash_algo = data32;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, &data_size);
    m_use_req_asym_algo = data16;

    if ((m_use_requester_capability_flags &
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0) {
        m_use_slot_id = 0xFF;
    }
    if (m_use_slot_id == 0xFF) {
        res = libspdm_read_responder_public_key(m_use_asym_algo, &data, &data_size);
        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_KEY,
                             &parameter, data, data_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_public_key fail!\n");
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
        res = libspdm_read_requester_public_key(m_use_req_asym_algo, &data, &data_size);
        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                             &parameter, data, data_size);
            /* Do not free it.*/
        } else {
            printf("read_requester_public_key fail!\n");
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
    } else {
        res = libspdm_read_responder_root_public_certificate(m_use_hash_algo,
                                                             m_use_asym_algo,
                                                             &data, &data_size,
                                                             &hash, &hash_size);
        if (res) {
            libspdm_x509_get_cert_from_cert_chain(
                (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                &root_cert, &root_cert_size);
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                             &parameter, (void *)root_cert, root_cert_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_root_public_certificate fail!\n");
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
        res = libspdm_read_responder_root_public_certificate_slot(1,
                                                                  m_use_hash_algo,
                                                                  m_use_asym_algo,
                                                                  &data1, &data1_size,
                                                                  &hash1, &hash1_size);
        if (res) {
            libspdm_x509_get_cert_from_cert_chain(
                (uint8_t *)data1 + sizeof(spdm_cert_chain_t) + hash1_size,
                data1_size - sizeof(spdm_cert_chain_t) - hash1_size, 0,
                &root_cert1, &root_cert1_size);
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                             &parameter, (void *)root_cert1, root_cert1_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_root_public_certificate fail!\n");
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
    }

    if (m_use_req_asym_algo != 0) {
        res = libspdm_read_requester_public_certificate_chain(m_use_hash_algo,
                                                              m_use_req_asym_algo,
                                                              &data, &data_size, NULL,
                                                              NULL);
        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

            for (index = 0; index < m_use_slot_count; index++) {
                parameter.additional_data[0] = index;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                 &parameter, data, data_size);
            }
            /* do not free it*/
        } else {
            printf("read_requester_public_certificate_chain fail!\n");
            free(m_spdm_context);
            m_spdm_context = NULL;
            return NULL;
        }
    }

    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PSK_HINT, NULL,
                              LIBSPDM_TEST_PSK_HINT_STRING,
                              sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_set_data - %x\n", (uint32_t)status);
    }

    if (m_save_state_file_name != NULL) {
        spdm_save_negotiated_state(spdm_context, true);
    }

    return m_spdm_context;
}
