/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint32_t hash_algo;
    uint32_t hash_size;
    uint8_t slot_mask;
    uint8_t slot_count;
    uint8_t total_digest_buffer[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
} spdm_certificate_test_buffer_t;
#pragma pack()

bool spdm_test_case_certificate_setup_vca_digest (void *test_context,
                                                  spdm_version_number_t spdm_version)
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
    spdm_certificate_test_buffer_t *test_buffer;
    size_t index;

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
                   sizeof(spdm_certificate_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_certificate_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_certificate_test_buffer_t);

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

    data_size = sizeof(test_buffer->hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &test_buffer->hash_algo,
                     &data_size);
    test_buffer->hash_size = libspdm_get_hash_size(test_buffer->hash_algo);

    status = libspdm_get_digest (spdm_context, &test_buffer->slot_mask,
                                 test_buffer->total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer->slot_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if ((test_buffer->slot_mask & (1 << index)) != 0) {
            test_buffer->slot_count++;
        }
    }

    spdm_test_context->test_scratch_buffer_size = offsetof(spdm_certificate_test_buffer_t,
                                                           total_digest_buffer) +
                                                  test_buffer->hash_size * test_buffer->slot_count;

    return true;
}

bool spdm_test_case_certificate_setup_version_any (void *test_context)
{
    return spdm_test_case_certificate_setup_vca_digest (test_context, 0);
}

bool spdm_test_case_certificate_setup_version_capabilities (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    uint32_t rsp_cap_flags;
    size_t data_size;
    spdm_version_number_t spdm_version;
    spdm_certificate_test_buffer_t *test_buffer;

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

    rsp_cap_flags = 0;
    data_size = sizeof(rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &rsp_cap_flags,
                     &data_size);
    if ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >=
                   sizeof(spdm_certificate_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_certificate_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_certificate_test_buffer_t);

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

void spdm_test_case_certificate_success_10 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_certificate_request_t spdm_request;
    spdm_certificate_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    spdm_cert_chain_t *spdm_cert_chain;
    uint8_t cert_chain_hash[LIBSPDM_MAX_HASH_SIZE];
    common_test_result_t test_result;
    spdm_certificate_test_buffer_t *test_buffer;
    uint8_t slot_id;
    uint8_t hash_index;
    bool result;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_certificate_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    hash_index = 0;
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((test_buffer->slot_mask & (0x1 << slot_id)) == 0) {
            continue;
        }
        common_test_record_test_message ("test slot - 0x%02x (hash index - 0x%02x)\n", slot_id,
                                         hash_index);

        cert_chain_buffer_size = 0;
        do {
            common_test_record_test_message ("test offset - 0x%04x\n", cert_chain_buffer_size);

            libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
            spdm_request.header.spdm_version = test_buffer->version;
            spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
            spdm_request.header.param1 = slot_id;
            spdm_request.header.param2 = 0;
            spdm_request.offset = (uint16_t)cert_chain_buffer_size;
            spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

            spdm_response = (void *)message;
            spdm_response_size = sizeof(message);
            libspdm_zero_mem(message, sizeof(message));
            status = libspdm_send_receive_data(spdm_context, NULL, false,
                                               &spdm_request, sizeof(spdm_request),
                                               spdm_response, &spdm_response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                    SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
                return;
            }

            if (spdm_response_size >= sizeof(spdm_certificate_response_t)) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, 1,
                test_result, "response size - %d", spdm_response_size);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            if (spdm_response->header.request_response_code == SPDM_CERTIFICATE) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, 2,
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
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, 3,
                test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            if ((spdm_response->portion_length > 0) &&
                (spdm_response->portion_length <= spdm_request.length)) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, 4,
                test_result, "response portion_length - 0x%04x", spdm_response->portion_length);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            libspdm_copy_mem (&cert_chain_buffer[cert_chain_buffer_size],
                              sizeof(cert_chain_buffer) - cert_chain_buffer_size,
                              spdm_response + 1,
                              spdm_response->portion_length);
            cert_chain_buffer_size += spdm_response->portion_length;
        } while (spdm_response->remainder_length != 0);

        spdm_cert_chain = (void *)cert_chain_buffer;

        if ((cert_chain_buffer_size > sizeof(spdm_cert_chain) + test_buffer->hash_size) &&
            (cert_chain_buffer_size == spdm_cert_chain->length)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE, SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10,
            5,
            test_result, "response cert chain buffer size - 0x%x, cert_chain.length - 0x%04x",
            cert_chain_buffer_size, spdm_cert_chain->length);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return;
        }

        result = libspdm_hash_all (test_buffer->hash_algo, cert_chain_buffer, cert_chain_buffer_size,
                          cert_chain_hash);
        if (!result) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE, SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "calc_cert_hash failure");
            return;
        }
        if (libspdm_const_compare_mem (cert_chain_hash,
                                       &test_buffer->total_digest_buffer[hash_index *
                                                                         test_buffer->hash_size],
                                       test_buffer->hash_size) == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE, SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10,
            6,
            test_result, "response cert chain hash");
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return;
        }

        hash_index++;
    }
}

void spdm_test_case_certificate_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_certificate_request_t spdm_request;
    spdm_certificate_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_certificate_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_certificate_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = 0;
        spdm_request.offset = 0;
        spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, sizeof(spdm_request),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, 2,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_certificate_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_certificate_request_t spdm_request;
    spdm_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_certificate_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
        SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, 1,
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
        SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
        SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, 2,
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
        SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
        SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, 3,
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
        SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
        SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, 4,
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
        SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
        SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_certificate_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_certificate_request_t spdm_request;
    spdm_get_certificate_request_t spdm_request_new;
    spdm_certificate_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_certificate_test_buffer_t *test_buffer;
    size_t index;
    uint8_t slot_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_certificate_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT * 2 + 2; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request,
                          sizeof(spdm_request));

        if (index < SPDM_MAX_SLOT_COUNT * 2) {
            slot_id = (uint8_t)index;
            if ((slot_id < SPDM_MAX_SLOT_COUNT) &&
                ((test_buffer->slot_mask & (0x1 << slot_id)) != 0)) {
                continue;
            }
            common_test_record_test_message ("test invalid slot - 0x%02x\n", slot_id);
            spdm_request_new.header.param1 = slot_id;
        } else if (index == SPDM_MAX_SLOT_COUNT * 2) {
            common_test_record_test_message ("test invalid offset - 0x%04x\n", 0xFFFF);
            spdm_request_new.offset = 0xFFFF;
        } else {
            common_test_record_test_message ("test invalid length - 0x%04x\n", 0);
            spdm_request_new.length = 0;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, sizeof(spdm_request_new),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, 1,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, 2,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, 3,
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
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
            SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_certificate[] = {
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, "spdm_test_case_certificate_success_10",
     spdm_test_case_certificate_success_10, spdm_test_case_certificate_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH,
     "spdm_test_case_certificate_version_mismatch", spdm_test_case_certificate_version_mismatch,
     spdm_test_case_certificate_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST,
     "spdm_test_case_certificate_unexpected_request",
     spdm_test_case_certificate_unexpected_request,
     spdm_test_case_certificate_setup_version_capabilities},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST,
     "spdm_test_case_certificate_invalid_request", spdm_test_case_certificate_invalid_request,
     spdm_test_case_certificate_setup_version_any},
    {COMMON_TEST_ID_END, NULL, NULL},
};
