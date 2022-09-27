/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint32_t rsp_cap_flags;
    uint32_t hash_algo;
    uint32_t hash_size;
    uint32_t asym_algo;
    uint32_t signature_size;
    uint16_t dhe_named_group;
    uint32_t dhe_key_size;
    uint8_t slot_mask;
    uint8_t slot_count;
    uint8_t total_digest_buffer[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
} spdm_key_exchange_rsp_test_buffer_t;
#pragma pack()

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint8_t session_policy;
    uint8_t reserved;
    uint8_t random_data[32];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} spdm_key_exchange_request_mine_t;

#pragma pack()

bool spdm_test_case_key_exchange_rsp_setup_vca_digest (void *test_context,
                                                       size_t spdm_version_count,
                                                       spdm_version_number_t *spdm_version,
                                                       bool hs_clear)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    spdm_version_number_t version;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    uint32_t data32;
    uint16_t data16;
    uint8_t data8;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;
    size_t index;
    uint8_t cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    if (spdm_version_count != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         spdm_version, sizeof(spdm_version_number_t) * spdm_version_count);
    }

    data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    if (hs_clear) {
        data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    }
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    status = libspdm_init_connection (spdm_context, false);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >=
                   sizeof(spdm_key_exchange_rsp_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_key_exchange_rsp_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_key_exchange_rsp_test_buffer_t);

    data_size = sizeof(version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &version, &data_size);
    test_buffer->version = (version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &test_buffer->rsp_cap_flags, &data_size);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) ||
        ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0)) {
        return false;
    }

    if (hs_clear) {
        if ((test_buffer->rsp_cap_flags &
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
            return false;
        }
    }

    data_size = sizeof(test_buffer->hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &test_buffer->hash_algo,
                     &data_size);
    test_buffer->hash_size = libspdm_get_hash_size(test_buffer->hash_algo);

    data_size = sizeof(test_buffer->asym_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &test_buffer->asym_algo,
                     &data_size);
    test_buffer->signature_size = libspdm_get_asym_signature_size(test_buffer->asym_algo);

    data_size = sizeof(test_buffer->dhe_named_group);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &test_buffer->dhe_named_group, &data_size);
    test_buffer->dhe_key_size = libspdm_get_dhe_pub_key_size(test_buffer->dhe_named_group);

    status = libspdm_get_digest (spdm_context, &test_buffer->slot_mask,
                                 test_buffer->total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    cert_chain_buffer_size = sizeof(cert_chain_buffer);
    status = libspdm_get_certificate (spdm_context, 0, &cert_chain_buffer_size, cert_chain_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer->slot_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if ((test_buffer->slot_mask & (1 << index)) != 0) {
            test_buffer->slot_count++;
        }
    }

    spdm_test_context->test_scratch_buffer_size = offsetof(spdm_key_exchange_rsp_test_buffer_t,
                                                           total_digest_buffer) +
                                                  test_buffer->hash_size * test_buffer->slot_count;

    return true;
}

bool spdm_test_case_key_exchange_rsp_setup_version_any (void *test_context)
{
    return spdm_test_case_key_exchange_rsp_setup_vca_digest (test_context, 0, NULL, false);
}

bool spdm_test_case_key_exchange_rsp_setup_version_11 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_key_exchange_rsp_setup_vca_digest (test_context,
                                                             LIBSPDM_ARRAY_SIZE(
                                                                 spdm_version), spdm_version,
                                                             false);
}

bool spdm_test_case_key_exchange_rsp_setup_version_11_hs_clear (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_key_exchange_rsp_setup_vca_digest (test_context,
                                                             LIBSPDM_ARRAY_SIZE(
                                                                 spdm_version), spdm_version, true);
}

bool spdm_test_case_key_exchange_rsp_setup_version_12 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_key_exchange_rsp_setup_vca_digest (test_context,
                                                             LIBSPDM_ARRAY_SIZE(
                                                                 spdm_version), spdm_version,
                                                             false);
}

bool spdm_test_case_key_exchange_rsp_setup_version_12_hs_clear (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_key_exchange_rsp_setup_vca_digest (test_context,
                                                             LIBSPDM_ARRAY_SIZE(
                                                                 spdm_version), spdm_version, true);
}

bool spdm_test_case_key_exchange_rsp_setup_version_capabilities (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    spdm_version_number_t spdm_version;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    status = libspdm_get_version (spdm_context, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    status = libspdm_get_capabilities (spdm_context);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >=
                   sizeof(spdm_key_exchange_rsp_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_key_exchange_rsp_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_key_exchange_rsp_test_buffer_t);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &test_buffer->rsp_cap_flags, &data_size);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) ||
        ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0)) {
        return false;
    }

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version,
                     &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    spdm_test_context->test_scratch_buffer_size = sizeof(test_buffer->version);

    return true;
}

void spdm_test_case_key_exchange_rsp_success_11_12 (void *test_context, uint8_t version,
                                                    bool hs_clear)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_exchange_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_key_exchange_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    common_test_result_t test_result;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;
    uint8_t slot_id;
    size_t dhe_key_size;
    uint8_t meas_hash_type_index;
    uint32_t meas_hash_size;
    uint32_t verify_data_size;
    uint8_t *ptr;
    void *dhe_context;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    uint32_t session_id;
    void *session_info;
    void *secured_message_context;
    size_t opaque_key_exchange_req_size;
    uint16_t *opaque_length_ptr;
    uint8_t *exchange_data_ptr;
    uint8_t *signature_ptr;
    uint8_t *verify_data_ptr;
    uint8_t th1_hash_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    uint8_t measurement_hash_type[] = {
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
        SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH,
    };
    common_test_case_id case_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_key_exchange_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    switch (version) {
    case SPDM_MESSAGE_VERSION_11:
        LIBSPDM_ASSERT (test_buffer->version == SPDM_MESSAGE_VERSION_11);
        if (hs_clear) {
            case_id = SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11_HS_CLEAR;
        } else {
            case_id = SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11;
        }
        break;
    case SPDM_MESSAGE_VERSION_12:
        LIBSPDM_ASSERT (test_buffer->version == SPDM_MESSAGE_VERSION_12);
        if (hs_clear) {
            case_id = SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12_HS_CLEAR;
        } else {
            case_id = SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12;
        }
        break;
    default:
        LIBSPDM_ASSERT(false);
        return;
    }

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((test_buffer->slot_mask & (0x1 << slot_id)) == 0) {
            continue;
        }
        common_test_record_test_message ("test slot - 0x%02x\n", slot_id);

        for (meas_hash_type_index = 0;
             meas_hash_type_index < LIBSPDM_ARRAY_SIZE(measurement_hash_type);
             meas_hash_type_index++) {
            if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) {
                if (measurement_hash_type[meas_hash_type_index] !=
                    SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH) {
                    continue;
                }
            }
            common_test_record_test_message ("test meas hash type - 0x%02x\n",
                                             measurement_hash_type[meas_hash_type_index]);

            status = libspdm_init_connection (spdm_context, false);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "init_connection failure");
                continue;
            }

            cert_chain_buffer_size = sizeof(cert_chain_buffer);
            status = libspdm_get_certificate (spdm_context, slot_id, &cert_chain_buffer_size,
                                              cert_chain_buffer);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "get_certificate failure");
                continue;
            }

            libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
            spdm_request.header.spdm_version = test_buffer->version;
            spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
            spdm_request.header.param1 = measurement_hash_type[meas_hash_type_index];
            spdm_request.header.param2 = slot_id;
            /* ignore spdm_request.random_data */
            req_session_id = libspdm_allocate_req_session_id(spdm_context);
            spdm_request.req_session_id = req_session_id;
            spdm_request.session_policy = 0;

            dhe_context = libspdm_secured_message_dhe_new(
                test_buffer->version,
                test_buffer->dhe_named_group, true);
            if (dhe_context == NULL) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "dhe_new failure");
                return;
            }
            dhe_key_size = test_buffer->dhe_key_size;
            ptr = spdm_request.exchange_data;
            result = libspdm_secured_message_dhe_generate_key(
                test_buffer->dhe_named_group,
                dhe_context, ptr, &dhe_key_size);
            if (!result) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "dhe_generate_key failure");
                return;
            }
            ptr += dhe_key_size;

            opaque_key_exchange_req_size =
                libspdm_get_opaque_data_supported_version_data_size(spdm_context);
            *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
            ptr += sizeof(uint16_t);
            status = libspdm_build_opaque_data_supported_version_data(
                spdm_context, &opaque_key_exchange_req_size, ptr);
            LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
            ptr += opaque_key_exchange_req_size;

            spdm_request_size = (size_t)ptr - (size_t)&spdm_request;

            spdm_response = (void *)message;
            spdm_response_size = sizeof(message);
            libspdm_zero_mem(message, sizeof(message));
            status = libspdm_send_receive_data(spdm_context, NULL, false,
                                               &spdm_request, spdm_request_size,
                                               spdm_response, &spdm_response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
                return;
            }

            if (measurement_hash_type[meas_hash_type_index] ==
                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH) {
                meas_hash_size = 0;
            } else {
                meas_hash_size = test_buffer->hash_size;
            }
            if (hs_clear) {
                verify_data_size = 0;
            } else {
                verify_data_size = test_buffer->hash_size;
            }
            opaque_length_ptr =
                (void *)((size_t)spdm_response + sizeof(spdm_key_exchange_response_t) +
                         test_buffer->dhe_key_size + meas_hash_size);
            if (spdm_response_size < sizeof(spdm_key_exchange_response_t) +
                test_buffer->dhe_key_size + meas_hash_size + sizeof(uint16_t) +
                test_buffer->signature_size + verify_data_size) {
                test_result = COMMON_TEST_RESULT_FAIL;
            } else {
                if (spdm_response_size < sizeof(spdm_key_exchange_response_t) +
                    test_buffer->dhe_key_size + meas_hash_size + sizeof(uint16_t) +
                    *opaque_length_ptr + test_buffer->signature_size + verify_data_size) {
                    test_result = COMMON_TEST_RESULT_FAIL;
                } else {
                    test_result = COMMON_TEST_RESULT_PASS;
                }
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 1,
                test_result, "response size - %d", spdm_response_size);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }
            exchange_data_ptr =
                (void *)((size_t)spdm_response + sizeof(spdm_key_exchange_response_t));
            signature_ptr = (void *)((size_t)spdm_response + sizeof(spdm_key_exchange_response_t) +
                                     test_buffer->dhe_key_size + meas_hash_size + sizeof(uint16_t) +
                                     *opaque_length_ptr);
            verify_data_ptr = (void *)(signature_ptr + test_buffer->signature_size);
            if (spdm_response->header.request_response_code == SPDM_KEY_EXCHANGE_RSP) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 2,
                test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }

            if (spdm_response->header.spdm_version == test_buffer->version) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 3,
                test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }

            if (spdm_response->mut_auth_requested == 0) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 4,
                test_result, "response mut_auth_requested - 0x%02x",
                spdm_response->mut_auth_requested);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }

            if (spdm_response->req_slot_id_param == 0) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 4,
                test_result, "response req_slot_id_param - 0x%02x",
                spdm_response->req_slot_id_param);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }

            rsp_session_id = spdm_response->rsp_session_id;
            session_id = (req_session_id << 16) | rsp_session_id;
            common_test_record_test_message ("test session_id - 0x%08x\n", session_id);
            session_info = libspdm_assign_session_id(spdm_context, session_id, false);
            if (session_info == NULL) {
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "assign_session_id failure");
                return;
            }
            secured_message_context = libspdm_get_secured_message_context_via_session_info(
                session_info);
            LIBSPDM_ASSERT (secured_message_context != NULL);

            status = libspdm_append_message_k(spdm_context, session_info, true, &spdm_request,
                                              spdm_request_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_k failure");
                return;
            }
            status = libspdm_append_message_k(spdm_context, session_info, true, spdm_response,
                                              (size_t)signature_ptr - (size_t)spdm_response);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_k failure");
                return;
            }
            result = libspdm_verify_key_exchange_rsp_signature(
                spdm_context, session_info, signature_ptr, test_buffer->signature_size);
            if (result) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 5,
                test_result, "response signature");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                libspdm_free_session_id(spdm_context, session_id);
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                return;
            }
            status = libspdm_append_message_k(spdm_context, session_info, true, signature_ptr,
                                              test_buffer->signature_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_k failure");
                return;
            }

            result = libspdm_secured_message_dhe_compute_key(
                test_buffer->dhe_named_group,
                dhe_context, exchange_data_ptr, test_buffer->dhe_key_size,
                secured_message_context);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                libspdm_secured_message_dhe_free(
                    test_buffer->dhe_named_group, dhe_context);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "dhe_compute_key failure");
                return;
            }

            libspdm_secured_message_dhe_free(
                test_buffer->dhe_named_group, dhe_context);

            result = libspdm_calculate_th1_hash(spdm_context, session_info, true,
                                                th1_hash_data);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "calculate_th1_hash failure");
                return;
            }

            result = libspdm_generate_session_handshake_key(
                secured_message_context, th1_hash_data);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_free_session_id(spdm_context, session_id);
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "generate_session_handshake_key failure");
                return;
            }

            if (!hs_clear) {
                result = libspdm_verify_key_exchange_rsp_hmac(
                    spdm_context, session_info, verify_data_ptr, test_buffer->hash_size);
                if (result) {
                    test_result = COMMON_TEST_RESULT_PASS;
                } else {
                    test_result = COMMON_TEST_RESULT_FAIL;
                }
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, 6,
                    test_result, "response verify_data");
                if (test_result == COMMON_TEST_RESULT_FAIL) {
                    libspdm_free_session_id(spdm_context, session_id);
                    return;
                }
                status = libspdm_append_message_k(spdm_context, session_info, true, verify_data_ptr,
                                                  test_buffer->hash_size);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    libspdm_free_session_id(spdm_context, session_id);
                    common_test_record_test_assertion (
                        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP, case_id, COMMON_TEST_ID_END,
                        COMMON_TEST_RESULT_NOT_TESTED, "append_message_k failure");
                    return;
                }
            }
            libspdm_reset_message_k (spdm_context, session_info);
            libspdm_free_session_id(spdm_context, session_id);
        }
    }
}

void spdm_test_case_key_exchange_rsp_success_11 (void *test_context)
{
    spdm_test_case_key_exchange_rsp_success_11_12 (test_context,
                                                   SPDM_MESSAGE_VERSION_11, false);
}

void spdm_test_case_key_exchange_rsp_success_11_hs_clear (void *test_context)
{
    spdm_test_case_key_exchange_rsp_success_11_12 (test_context,
                                                   SPDM_MESSAGE_VERSION_11, true);
}

void spdm_test_case_key_exchange_rsp_success_12 (void *test_context)
{
    spdm_test_case_key_exchange_rsp_success_11_12 (test_context,
                                                   SPDM_MESSAGE_VERSION_12, false);
}

void spdm_test_case_key_exchange_rsp_success_12_hs_clear (void *test_context)
{
    spdm_test_case_key_exchange_rsp_success_11_12 (test_context,
                                                   SPDM_MESSAGE_VERSION_12, true);
}

void spdm_test_case_key_exchange_rsp_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_exchange_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_key_exchange_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t *ptr;
    size_t dhe_key_size;
    size_t opaque_key_exchange_req_size;
    void *dhe_context;
    uint16_t req_session_id;
    bool result;
    common_test_result_t test_result;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_key_exchange_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
        spdm_request.header.param1 = SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
        spdm_request.header.param2 = 0;
        /* ignore spdm_request.random_data */
        req_session_id = libspdm_allocate_req_session_id(spdm_context);
        spdm_request.req_session_id = req_session_id;
        spdm_request.session_policy = 0;

        dhe_context = libspdm_secured_message_dhe_new(
            test_buffer->version,
            test_buffer->dhe_named_group, true);
        if (dhe_context == NULL) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
                SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "dhe_new failure");
            return;
        }
        dhe_key_size = test_buffer->dhe_key_size;
        ptr = spdm_request.exchange_data;
        result = libspdm_secured_message_dhe_generate_key(
            test_buffer->dhe_named_group,
            dhe_context, ptr, &dhe_key_size);
        if (!result) {
            libspdm_secured_message_dhe_free(
                test_buffer->dhe_named_group, dhe_context);
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
                SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "dhe_generate_key failure");
            return;
        }
        ptr += dhe_key_size;

        opaque_key_exchange_req_size =
            libspdm_get_opaque_data_supported_version_data_size(spdm_context);
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
        ptr += sizeof(uint16_t);
        status = libspdm_build_opaque_data_supported_version_data(
            spdm_context, &opaque_key_exchange_req_size, ptr);
        LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
        ptr += opaque_key_exchange_req_size;

        spdm_request_size = (size_t)ptr - (size_t)&spdm_request;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
                SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.param1 == SPDM_ERROR_CODE_VERSION_MISMATCH) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_key_exchange_rsp_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_exchange_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_key_exchange_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t *ptr;
    common_test_result_t test_result;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
    spdm_request.header.param1 = SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    spdm_request.header.param2 = 0;
    spdm_request.req_session_id = 0;
    spdm_request.session_policy = 0;
    ptr = spdm_request.exchange_data;
    ptr += test_buffer->dhe_key_size;
    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);
    spdm_request_size = (size_t)ptr - (size_t)&spdm_request;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == test_buffer->version) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_UNEXPECTED_REQUEST) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_key_exchange_rsp_unexpected_request_in_session (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_exchange_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_key_exchange_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint8_t *ptr;
    size_t dhe_key_size;
    size_t opaque_key_exchange_req_size;
    void *dhe_context;
    uint16_t req_session_id;
    bool result;
    common_test_result_t test_result;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;
    uint32_t session_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    status = libspdm_start_session (spdm_context, false,
                                    SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                    0, 0, &session_id, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "start_session failure");
        return;
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
    spdm_request.header.param1 = SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    spdm_request.header.param2 = 0;
    req_session_id = libspdm_allocate_req_session_id(spdm_context);
    spdm_request.req_session_id = req_session_id;
    spdm_request.session_policy = 0;

    dhe_context = libspdm_secured_message_dhe_new(
        test_buffer->version,
        test_buffer->dhe_named_group, true);
    if (dhe_context == NULL) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "dhe_new failure");
        return;
    }
    dhe_key_size = test_buffer->dhe_key_size;
    ptr = spdm_request.exchange_data;
    result = libspdm_secured_message_dhe_generate_key(
        test_buffer->dhe_named_group,
        dhe_context, ptr, &dhe_key_size);
    if (!result) {
        libspdm_secured_message_dhe_free(
            test_buffer->dhe_named_group, dhe_context);
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "dhe_generate_key failure");
        return;
    }
    ptr += dhe_key_size;

    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    status = libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
    ptr += opaque_key_exchange_req_size;

    spdm_request_size = (size_t)ptr - (size_t)&spdm_request;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &session_id, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == test_buffer->version) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_UNEXPECTED_REQUEST) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
        SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_key_exchange_rsp_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_exchange_request_mine_t spdm_request;
    spdm_key_exchange_request_mine_t spdm_request_new;
    size_t spdm_request_size;
    spdm_key_exchange_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t *ptr;
    size_t dhe_key_size;
    size_t opaque_key_exchange_req_size;
    void *dhe_context;
    uint16_t req_session_id;
    bool result;
    common_test_result_t test_result;
    spdm_key_exchange_rsp_test_buffer_t *test_buffer;
    size_t index;
    uint8_t slot_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_key_exchange_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
    spdm_request.header.param1 = SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    spdm_request.header.param2 = 0;
    /* ignore spdm_request.random_data */
    req_session_id = libspdm_allocate_req_session_id(spdm_context);
    spdm_request.req_session_id = req_session_id;
    spdm_request.session_policy = 0;

    dhe_context = libspdm_secured_message_dhe_new(
        test_buffer->version,
        test_buffer->dhe_named_group, true);
    if (dhe_context == NULL) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "dhe_new failure");
        return;
    }
    dhe_key_size = test_buffer->dhe_key_size;
    ptr = spdm_request.exchange_data;
    result = libspdm_secured_message_dhe_generate_key(
        test_buffer->dhe_named_group,
        dhe_context, ptr, &dhe_key_size);
    if (!result) {
        libspdm_secured_message_dhe_free(
            test_buffer->dhe_named_group, dhe_context);
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "dhe_generate_key failure");
        return;
    }
    ptr += dhe_key_size;

    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    status = libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
    ptr += opaque_key_exchange_req_size;

    spdm_request_size = (size_t)ptr - (size_t)&spdm_request;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT * 2 + 2; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request,
                          spdm_request_size);

        if (index < SPDM_MAX_SLOT_COUNT * 2) {
            slot_id = (uint8_t)index;
            if ((slot_id < SPDM_MAX_SLOT_COUNT) &&
                ((test_buffer->slot_mask & (0x1 << slot_id)) != 0)) {
                continue;
            }
            common_test_record_test_message ("test invalid slot - 0x%02x\n", slot_id);
            spdm_request_new.header.param2 = slot_id;
        } else if (index == SPDM_MAX_SLOT_COUNT * 2) {
            common_test_record_test_message ("test invalid meas_hash_type - 0x%02x\n",
                                             SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH +
                                             1);
            spdm_request_new.header.param1 =
                SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH + 1;
        } else {
            common_test_record_test_message ("test invalid meas_hash_type - 0x%02x\n",
                                             SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH - 1);
            spdm_request_new.header.param1 = SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH - 1;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
                SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.param1 == SPDM_ERROR_CODE_INVALID_REQUEST) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
            SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_key_exchange_rsp[] = {
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11,
     "spdm_test_case_key_exchange_rsp_success_11", spdm_test_case_key_exchange_rsp_success_11,
     spdm_test_case_key_exchange_rsp_setup_version_11},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11_HS_CLEAR,
     "spdm_test_case_key_exchange_rsp_success_11_hs_clear",
     spdm_test_case_key_exchange_rsp_success_11_hs_clear,
     spdm_test_case_key_exchange_rsp_setup_version_11_hs_clear},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH,
     "spdm_test_case_key_exchange_rsp_version_mismatch",
     spdm_test_case_key_exchange_rsp_version_mismatch,
     spdm_test_case_key_exchange_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST,
     "spdm_test_case_key_exchange_rsp_unexpected_request",
     spdm_test_case_key_exchange_rsp_unexpected_request,
     spdm_test_case_key_exchange_rsp_setup_version_capabilities},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
     "spdm_test_case_key_exchange_rsp_unexpected_request_in_session",
     spdm_test_case_key_exchange_rsp_unexpected_request_in_session,
     spdm_test_case_key_exchange_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST,
     "spdm_test_case_key_exchange_rsp_invalid_request",
     spdm_test_case_key_exchange_rsp_invalid_request,
     spdm_test_case_key_exchange_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12,
     "spdm_test_case_key_exchange_rsp_success_12", spdm_test_case_key_exchange_rsp_success_12,
     spdm_test_case_key_exchange_rsp_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12_HS_CLEAR,
     "spdm_test_case_key_exchange_rsp_success_12_hs_clear",
     spdm_test_case_key_exchange_rsp_success_12_hs_clear,
     spdm_test_case_key_exchange_rsp_setup_version_12_hs_clear},
    {COMMON_TEST_ID_END, NULL, NULL},
};
