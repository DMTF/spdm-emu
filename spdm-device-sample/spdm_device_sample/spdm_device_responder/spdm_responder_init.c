/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"
#include "spdm_device_secret_lib/spdm_device_secret_lib_internal.h"

uint8_t m_scratch_buffer[LIBSPDM_SCRATCH_BUFFER_SIZE];

bool m_send_receive_buffer_acquired = false;
uint8_t m_send_receive_buffer[LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE];
size_t m_send_receive_buffer_size;

libspdm_return_t spdm_responder_send_message(void *spdm_context,
                                             size_t message_size, const void *message,
                                             uint64_t timeout)
{
    size_t index;
    const uint32_t *msg;
    uint32_t data32;

    LIBSPDM_ASSERT((message_size % 3) == 0);
    msg = message;

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_STATUS_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_STATUS_BIT_BUSY) == 0) {
            break;
        }
    }

    for (index = 0; index < message_size / 4; index++) {
        spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_READ_DATA_MAILBOX_OFFSET, msg[index]);
    }

    spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_STATUS_OFFSET,
                                   PCI_EXPRESS_REG_DOE_STATUS_BIT_DATA_READY);
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_responder_receive_message(void *spdm_context,
                                                size_t *message_size,
                                                void **message,
                                                uint64_t timeout)
{
    size_t index;
    uint32_t *msg;
    uint32_t data32;

    LIBSPDM_ASSERT (*message == m_send_receive_buffer);
    LIBSPDM_ASSERT((m_send_receive_buffer_size % 3) == 0);
    msg = *message;

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_STATUS_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_STATUS_BIT_BUSY) == 0) {
            break;
        } else {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    }

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_CONTROL_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_CONTROL_BIT_GO) != 0) {
            break;
        } else {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    }

    for (index = 0; index < m_send_receive_buffer_size / 4; index++) {
        msg[index] = spdm_dev_pci_cfg_doe_read_32 (PCI_EXPRESS_REG_DOE_WRITE_DATA_MAILBOX_OFFSET);
    }
    *message_size = m_send_receive_buffer_size;

    spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_CONTROL_OFFSET, 0);
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

void *spdm_server_init(void)
{
    void *spdm_context;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    void *data;
    size_t data_size;

    spdm_context = (void *)allocate_pool(libspdm_get_context_size());
    if (spdm_context == NULL) {
        return NULL;
    }
    libspdm_init_context(spdm_context);

    /* io function callback */
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, sizeof(m_scratch_buffer));

    libspdm_register_device_io_func(spdm_context, spdm_responder_send_message,
                                    spdm_responder_receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                                          libspdm_transport_pci_doe_encode_message,
                                          libspdm_transport_pci_doe_decode_message,
                                          libspdm_transport_pci_doe_get_header_size);
    libspdm_register_device_buffer_func(spdm_context,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    /* version */
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data16 = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &data16, sizeof(data16));

    /* capabilities */
    data8 = 0;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

    data32 =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP
    ;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    /* algorithm */
    data8 = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    data8 = 0xF0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                     &data8, sizeof(data8));

    /* certificate */
    libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        &data, &data_size,
        NULL, NULL);
    parameter.additional_data[0] = 0;
    libspdm_set_data(spdm_context,
                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                     &parameter, data, data_size);

    /* spdm function callback */
    libspdm_register_get_response_func(
        spdm_context, spdm_get_response_vendor_defined_request);

    return spdm_context;
}
