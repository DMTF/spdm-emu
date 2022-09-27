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
    uint8_t slot_mask;
    uint8_t slot_count;
    uint8_t total_digest_buffer[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_rsp_test_buffer_t;
#pragma pack()

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

#pragma pack()

bool spdm_test_case_finish_rsp_setup_vca_digest (void *test_context,
                                                 size_t spdm_version_count,
                                                 spdm_version_number_t *spdm_version, bool hs_clear)
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
    spdm_finish_rsp_test_buffer_t *test_buffer;
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
                   sizeof(spdm_finish_rsp_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_finish_rsp_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_finish_rsp_test_buffer_t);

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

    spdm_test_context->test_scratch_buffer_size = offsetof(spdm_finish_rsp_test_buffer_t,
                                                           total_digest_buffer) +
                                                  test_buffer->hash_size * test_buffer->slot_count;

    return true;
}

bool spdm_test_case_finish_rsp_setup_version_any (void *test_context)
{
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context, 0, NULL, false);
}

bool spdm_test_case_finish_rsp_setup_version_any_hs_clear (void *test_context)
{
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context, 0, NULL, true);
}

bool spdm_test_case_finish_rsp_setup_version_11 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context,
                                                       LIBSPDM_ARRAY_SIZE(
                                                           spdm_version), spdm_version, false);
}

bool spdm_test_case_finish_rsp_setup_version_11_hs_clear (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context,
                                                       LIBSPDM_ARRAY_SIZE(
                                                           spdm_version), spdm_version, true);
}

bool spdm_test_case_finish_rsp_setup_version_12 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context,
                                                       LIBSPDM_ARRAY_SIZE(
                                                           spdm_version), spdm_version, false);
}

bool spdm_test_case_finish_rsp_setup_version_12_hs_clear (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_finish_rsp_setup_vca_digest (test_context,
                                                       LIBSPDM_ARRAY_SIZE(
                                                           spdm_version), spdm_version, true);
}

bool spdm_test_case_finish_rsp_setup_version_capabilities (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    spdm_version_number_t spdm_version;
    spdm_finish_rsp_test_buffer_t *test_buffer;

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
                   sizeof(spdm_finish_rsp_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_finish_rsp_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_finish_rsp_test_buffer_t);

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

void spdm_test_case_finish_rsp_success_11_12 (void *test_context, uint8_t version, bool hs_clear)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;
    uint8_t slot_id;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    uint32_t verify_data_size;
    uint8_t *ptr;
    void *session_info;
    uint8_t *verify_data_ptr;
    uint8_t th2_hash_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    common_test_case_id case_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_finish_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    switch (version) {
    case SPDM_MESSAGE_VERSION_11:
        LIBSPDM_ASSERT (test_buffer->version == SPDM_MESSAGE_VERSION_11);
        if (hs_clear) {
            case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11_HS_CLEAR;
        } else {
            case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11;
        }
        break;
    case SPDM_MESSAGE_VERSION_12:
        LIBSPDM_ASSERT (test_buffer->version == SPDM_MESSAGE_VERSION_12);
        if (hs_clear) {
            case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12_HS_CLEAR;
        } else {
            case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12;
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

        status = libspdm_init_connection (spdm_context, false);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "init_connection failure");
            continue;
        }

        cert_chain_buffer_size = sizeof(cert_chain_buffer);
        status = libspdm_get_certificate (spdm_context, slot_id, &cert_chain_buffer_size,
                                          cert_chain_buffer);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "get_certificate failure");
            continue;
        }

        status = libspdm_send_receive_key_exchange (spdm_context,
                                                    SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                    slot_id, 0, &session_id, NULL, &req_slot_id_param,
                                                    NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
            continue;
        }

        session_info =
            libspdm_get_session_info_via_session_id(spdm_context, session_id);
        LIBSPDM_ASSERT (session_info != NULL);

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = test_buffer->version;
        spdm_request.header.request_response_code = SPDM_FINISH;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = 0;

        status = libspdm_append_message_f(spdm_context, session_info, true,
                                          (uint8_t *)&spdm_request,
                                          sizeof(spdm_finish_request_t));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
            continue;
        }
        ptr = spdm_request.verify_data;
        result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
        if (!result) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
            continue;
        }
        status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                          test_buffer->hash_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
            continue;
        }

        spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        if (hs_clear) {
            status = libspdm_send_receive_data(spdm_context, NULL, false,
                                               &spdm_request, spdm_request_size,
                                               spdm_response, &spdm_response_size);
        } else {
            status = libspdm_send_receive_data(spdm_context, session_info, false,
                                               &spdm_request, spdm_request_size,
                                               spdm_response, &spdm_response_size);
        }
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            return;
        }

        if (hs_clear) {
            verify_data_size = test_buffer->hash_size;
        } else {
            verify_data_size = 0;
        }
        if (spdm_response_size < sizeof(spdm_finish_response_t) + verify_data_size) {
            test_result = COMMON_TEST_RESULT_FAIL;
        } else {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return;
        }
        verify_data_ptr = (void *)((size_t)spdm_response + sizeof(spdm_finish_response_t));
        if (spdm_response->header.request_response_code == SPDM_FINISH_RSP) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 2,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return;
        }

        status = libspdm_append_message_f(spdm_context, session_info, true, spdm_response,
                                          sizeof(spdm_finish_response_t));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "append_message_k failure");
            return;
        }

        if (hs_clear) {
            result = libspdm_verify_finish_rsp_hmac(
                spdm_context, session_info, verify_data_ptr, test_buffer->hash_size);
            if (result) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 4,
                test_result, "response verify_data");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }
            status = libspdm_append_message_f(spdm_context, session_info, true, verify_data_ptr,
                                              test_buffer->hash_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
                return;
            }
        }

        result = libspdm_calculate_th2_hash(spdm_context, session_info, true,
                                            th2_hash_data);
        if (!result) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "calculate_th2_hash failure");
            return;
        }
    }
}

void spdm_test_case_finish_rsp_success_11 (void *test_context)
{
    spdm_test_case_finish_rsp_success_11_12 (test_context,
                                             SPDM_MESSAGE_VERSION_11, false);
}

void spdm_test_case_finish_rsp_success_11_hs_clear (void *test_context)
{
    spdm_test_case_finish_rsp_success_11_12 (test_context,
                                             SPDM_MESSAGE_VERSION_11, true);
}

void spdm_test_case_finish_rsp_success_12 (void *test_context)
{
    spdm_test_case_finish_rsp_success_11_12 (test_context,
                                             SPDM_MESSAGE_VERSION_12, false);
}

void spdm_test_case_finish_rsp_success_12_hs_clear (void *test_context)
{
    spdm_test_case_finish_rsp_success_11_12 (test_context,
                                             SPDM_MESSAGE_VERSION_12, true);
}

void spdm_test_case_finish_rsp_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    uint8_t *ptr;
    void *session_info;
    bool result;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_finish_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    status = libspdm_send_receive_key_exchange (spdm_context,
                                                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                0, 0, &session_id, NULL, &req_slot_id_param, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
        return;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_FINISH;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = 0;

        session_info =
            libspdm_get_session_info_via_session_id(spdm_context, session_id);
        LIBSPDM_ASSERT (session_info != NULL);

        status = libspdm_append_message_f(spdm_context, session_info, true,
                                          (uint8_t *)&spdm_request,
                                          sizeof(spdm_finish_request_t));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
            continue;
        }
        ptr = spdm_request.verify_data;
        result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
        if (!result) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
            continue;
        }
        status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                          test_buffer->hash_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
            continue;
        }

        spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, session_info, false,
                                           &spdm_request, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, 2,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_finish_rsp_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_FINISH;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, 1,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, 2,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, 3,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, 4,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_finish_rsp_unexpected_request_in_session (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint32_t session_id;
    uint8_t *ptr;
    void *session_info;
    bool result;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;

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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "start_session failure");
        return;
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_FINISH;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT (session_info != NULL);

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)&spdm_request,
                                      sizeof(spdm_finish_request_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }
    ptr = spdm_request.verify_data;
    result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
        return;
    }
    status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                      test_buffer->hash_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }

    spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &session_id, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, 1,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, 2,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, 3,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, 4,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
        SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_finish_rsp_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    spdm_finish_request_mine_t spdm_request_new;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    uint8_t *ptr;
    void *session_info;
    bool result;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;
    size_t index;
    uint8_t slot_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_finish_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    status = libspdm_send_receive_key_exchange (spdm_context,
                                                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                0, 0, &session_id, NULL, &req_slot_id_param, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
        return;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT (session_info != NULL);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_FINISH;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)&spdm_request,
                                      sizeof(spdm_finish_request_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }
    ptr = spdm_request.verify_data;
    result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
        return;
    }
    status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                      test_buffer->hash_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }

    spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT * 2 + 1; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request,
                          spdm_request_size);

        if (index < SPDM_MAX_SLOT_COUNT * 2) {
            slot_id = (uint8_t)index;
            if (slot_id == 0) {
                continue;
            }
            common_test_record_test_message ("test invalid slot - 0x%02x\n", slot_id);
            spdm_request_new.header.param2 = slot_id;
        } else {
            common_test_record_test_message ("test invalid size - 0x%x\n", spdm_request_size);
            spdm_request_size = sizeof(spdm_finish_request_t);
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, session_info, false,
                                           &spdm_request_new, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, 1,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, 2,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, 3,
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
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_common (void *test_context,
                                                                         bool hs_clear)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    uint8_t *ptr;
    void *session_info;
    bool result;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;
    common_test_case_id case_id;
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_finish_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    if (hs_clear) {
        case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA_HS_CLEAR;
    } else {
        case_id = SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA;
    }

    status = libspdm_send_receive_key_exchange (spdm_context,
                                                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                0, 0, &session_id, NULL, &req_slot_id_param, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
        return;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT (session_info != NULL);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_FINISH;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)&spdm_request,
                                      sizeof(spdm_finish_request_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }
    ptr = spdm_request.verify_data;
    result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
        return;
    }
    for (index = 0; index < test_buffer->hash_size; index++) {
        ptr[index] = ptr[index] ^ 0xFF;
    }
    status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                      test_buffer->hash_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }

    spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    if (hs_clear) {
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, spdm_request_size,
                                           spdm_response, &spdm_response_size);
    } else {
        status = libspdm_send_receive_data(spdm_context, session_info, false,
                                           &spdm_request, spdm_request_size,
                                           spdm_response, &spdm_response_size);
    }
    if (LIBSPDM_STATUS_IS_ERROR(status) && (status != LIBSPDM_STATUS_SESSION_MSG_ERROR)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (status == LIBSPDM_STATUS_SESSION_MSG_ERROR) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 1,
            COMMON_TEST_RESULT_PASS, "response size");
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 2,
            COMMON_TEST_RESULT_PASS, "response code");
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 3,
            COMMON_TEST_RESULT_PASS, "response version");
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 4,
            COMMON_TEST_RESULT_PASS, "response param1");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 1,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 2,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, case_id, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
}

void spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data (void *test_context)
{
    spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_common (test_context, false);
}

void spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_hs_clear (void *test_context)
{
    spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_common (test_context, true);
}

void spdm_test_case_finish_rsp_session_required (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_finish_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_finish_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    uint8_t *ptr;
    void *session_info;
    bool result;
    common_test_result_t test_result;
    spdm_finish_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_finish_rsp_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    status = libspdm_send_receive_key_exchange (spdm_context,
                                                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                0, 0, &session_id, NULL, &req_slot_id_param, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
        return;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT (session_info != NULL);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_FINISH;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)&spdm_request,
                                      sizeof(spdm_finish_request_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }
    ptr = spdm_request.verify_data;
    result = libspdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "generate_finish_req_hmac failure");
        return;
    }
    status = libspdm_append_message_f(spdm_context, session_info, true, ptr,
                                      test_buffer->hash_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "append_message_f failure");
        return;
    }

    spdm_request_size = sizeof(spdm_finish_request_t) + test_buffer->hash_size;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
            SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
        1,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
        2,
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
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
        3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_SESSION_REQUIRED) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_FINISH_RSP, SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
        4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
}

common_test_case_t m_spdm_test_group_finish_rsp[] = {
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11, "spdm_test_case_finish_rsp_success_11",
     spdm_test_case_finish_rsp_success_11, spdm_test_case_finish_rsp_setup_version_11},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11_HS_CLEAR,
     "spdm_test_case_finish_rsp_success_11_hs_clear",
     spdm_test_case_finish_rsp_success_11_hs_clear,
     spdm_test_case_finish_rsp_setup_version_11_hs_clear},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH,
     "spdm_test_case_finish_rsp_version_mismatch", spdm_test_case_finish_rsp_version_mismatch,
     spdm_test_case_finish_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST,
     "spdm_test_case_finish_rsp_unexpected_request",
     spdm_test_case_finish_rsp_unexpected_request,
     spdm_test_case_finish_rsp_setup_version_capabilities},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION,
     "spdm_test_case_finish_rsp_unexpected_request_in_session",
     spdm_test_case_finish_rsp_unexpected_request_in_session,
     spdm_test_case_finish_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST,
     "spdm_test_case_finish_rsp_invalid_request", spdm_test_case_finish_rsp_invalid_request,
     spdm_test_case_finish_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA,
     "spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data",
     spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data,
     spdm_test_case_finish_rsp_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA_HS_CLEAR,
     "spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_hs_clear",
     spdm_test_case_finish_rsp_decrypt_error_invalid_verify_data_hs_clear,
     spdm_test_case_finish_rsp_setup_version_any_hs_clear},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12, "spdm_test_case_finish_rsp_success_12",
     spdm_test_case_finish_rsp_success_12, spdm_test_case_finish_rsp_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12_HS_CLEAR,
     "spdm_test_case_finish_rsp_success_12_hs_clear",
     spdm_test_case_finish_rsp_success_12_hs_clear,
     spdm_test_case_finish_rsp_setup_version_12_hs_clear},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
     "spdm_test_case_finish_rsp_session_required", spdm_test_case_finish_rsp_session_required,
     spdm_test_case_finish_rsp_setup_version_12},
    {COMMON_TEST_ID_END, NULL, NULL},
};
