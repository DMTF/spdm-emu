/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint8_t reserved[3];
    uint32_t session_id;
} spdm_key_update_ack_test_buffer_t;
#pragma pack()

bool spdm_test_case_key_update_ack_setup_session (void *test_context,
                                                  spdm_version_number_t spdm_version,
                                                  bool need_session)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    uint32_t rsp_cap_flags;
    size_t data_size;
    uint32_t data32;
    uint16_t data16;
    uint8_t data8;
    spdm_key_update_ack_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    if (spdm_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, sizeof(spdm_version));
    }

    data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
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
                   sizeof(spdm_key_update_ack_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_key_update_ack_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_key_update_ack_test_buffer_t);

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version,
                     &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    rsp_cap_flags = 0;
    data_size = sizeof(rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &rsp_cap_flags,
                     &data_size);
    if ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
        return false;
    }

    if (((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) ||
        ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) ||
        ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP) == 0) ) {
        return false;
    }

    status = libspdm_get_certificate (spdm_context, 0, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (need_session) {
        status = libspdm_start_session (spdm_context, false,
                                        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                        0, 0, &test_buffer->session_id, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
    }

    return true;
}

bool spdm_test_case_key_update_ack_setup_version_any (void *test_context)
{
    return spdm_test_case_key_update_ack_setup_session (test_context, 0, true);
}

bool spdm_test_case_key_update_ack_setup_version_12 (void *test_context)
{
    return spdm_test_case_key_update_ack_setup_session (test_context,
                                                        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        true);
}

bool spdm_test_case_key_update_ack_setup_version_any_session_cap (void *test_context)
{
    return spdm_test_case_key_update_ack_setup_session (test_context, 0, false);
}

void spdm_test_case_key_update_ack_success_11_dhe (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_update_request_t spdm_request;
    spdm_key_update_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_key_update_ack_test_buffer_t *test_buffer;
    bool result;
    libspdm_session_info_t *session_info;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_key_update_ack_test_buffer_t));

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, test_buffer->session_id);
    LIBSPDM_ASSERT (session_info != NULL);

    /* update key */
    common_test_record_test_message ("test update key\n");

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    spdm_request.header.param2 = 0x0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));

    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_key_update_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_KEY_UPDATE_ACK) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 2,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == spdm_request.header.param1) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == spdm_request.header.param2) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    result = libspdm_create_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "create_update_session_data_key(Req) failure");
        return;
    }
    result = libspdm_activate_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_REQUESTER, true);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "activate_update_session_data_key(Req) failure");
        return;
    }

    /* update key */
    common_test_record_test_message ("test verify new key\n");

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    spdm_request.header.param2 = 0x0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_key_update_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 6,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_KEY_UPDATE_ACK) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 7,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 8,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == spdm_request.header.param1) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 9,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == spdm_request.header.param2) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 10,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    /* update all keys */
    common_test_record_test_message ("test update all keys\n");

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
    spdm_request.header.param2 = 0x0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));

    result = libspdm_create_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "create_update_session_data_key(Rsp) failure");
        return;
    }

    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_key_update_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 11,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_KEY_UPDATE_ACK) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 12,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 13,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == spdm_request.header.param1) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 14,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == spdm_request.header.param2) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 15,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    result = libspdm_activate_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, true);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "activate_update_session_data_key(Rsp) failure");
        return;
    }

    result = libspdm_create_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "create_update_session_data_key(Req) failure");
        return;
    }
    result = libspdm_activate_update_session_data_key(
        session_info->secured_message_context,
        LIBSPDM_KEY_UPDATE_ACTION_REQUESTER, true);
    if (!result) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "activate_update_session_data_key(Req) failure");
        return;
    }

    /* verify key */
    common_test_record_test_message ("test verify new key\n");

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    spdm_request.header.param2 = 0x0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_key_update_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 16,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_KEY_UPDATE_ACK) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 17,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 18,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param1 == spdm_request.header.param1) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 19,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.param2 == spdm_request.header.param2) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, 20,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }
}

void spdm_test_case_key_update_ack_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_update_request_t spdm_request;
    spdm_key_update_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_key_update_ack_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_key_update_ack_test_buffer_t));

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
        spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
        spdm_request.header.param2 = 0;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                           &spdm_request, sizeof(spdm_request),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
                SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION,
                COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, 1,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, 2,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, 3,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_key_update_ack_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_update_request_t spdm_request;
    spdm_key_update_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_key_update_ack_test_buffer_t *test_buffer;
    uint8_t invalid_operation[] = {
        SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY - 1,
        SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_key_update_ack_test_buffer_t));

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(invalid_operation); index++) {
        common_test_record_test_message ("test invalid_operation - 0x%02x\n",
                                         invalid_operation[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = test_buffer->version;
        spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
        spdm_request.header.param1 = invalid_operation[index];
        spdm_request.header.param2 = 0;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                           &spdm_request, sizeof(spdm_request),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
                SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION,
                COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, 1,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, 2,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, 3,
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
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_key_update_ack_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_update_request_t spdm_request;
    spdm_key_update_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_key_update_ack_test_buffer_t *test_buffer;
    uint8_t req_slot_id_param;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_key_update_ack_test_buffer_t));

    status = libspdm_send_receive_key_exchange (spdm_context,
                                                SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                0, 0, &test_buffer->session_id, NULL,
                                                &req_slot_id_param, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS,
            SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "key_exchange failure");
        return;
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    spdm_request.header.param2 = 0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, 1,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, 2,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, 3,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, 4,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_key_update_ack_session_required (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_key_update_request_t spdm_request;
    spdm_key_update_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_key_update_ack_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_key_update_ack_test_buffer_t));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    spdm_request.header.param2 = 0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
            SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, 1,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, 2,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, 3,
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
        SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
        SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }
}

common_test_case_t m_spdm_test_group_key_update_ack[] = {
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION,
     "spdm_test_case_key_update_ack_success_11_dhe",
     spdm_test_case_key_update_ack_success_11_dhe,
     spdm_test_case_key_update_ack_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION,
     "spdm_test_case_key_update_ack_version_mismatch",
     spdm_test_case_key_update_ack_version_mismatch,
     spdm_test_case_key_update_ack_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION,
     "spdm_test_case_key_update_ack_invalid_request",
     spdm_test_case_key_update_ack_invalid_request,
     spdm_test_case_key_update_ack_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
     "spdm_test_case_key_update_ack_unexpected_request",
     spdm_test_case_key_update_ack_unexpected_request,
     spdm_test_case_key_update_ack_setup_version_any_session_cap},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED,
     "spdm_test_case_key_update_ack_session_required",
     spdm_test_case_key_update_ack_session_required,
     spdm_test_case_key_update_ack_setup_version_12},
    {COMMON_TEST_ID_END, NULL, NULL},
};
