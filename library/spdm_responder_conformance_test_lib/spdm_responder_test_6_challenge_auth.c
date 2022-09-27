/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

#define SPDM_MESSAGE_A_MASK_VCA             0x1
#define SPDM_MESSAGE_B_MASK_GET_DIGESTS     0x2
#define SPDM_MESSAGE_B_MASK_GET_CERTIFICATE 0x4

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint32_t rsp_cap_flags;
    uint32_t hash_algo;
    uint32_t hash_size;
    uint32_t asym_algo;
    uint32_t signature_size;
    uint8_t slot_mask;
    uint8_t slot_count;
    uint8_t total_digest_buffer[SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE];
} spdm_challenge_auth_test_buffer_t;
#pragma pack()

bool spdm_test_case_challenge_auth_setup_vca_digest (void *test_context,
                                                     size_t spdm_version_count,
                                                     spdm_version_number_t *spdm_version)
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
    spdm_challenge_auth_test_buffer_t *test_buffer;
    size_t index;

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
                   sizeof(spdm_challenge_auth_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_challenge_auth_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_challenge_auth_test_buffer_t);

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
        ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0)) {
        return false;
    }

    data_size = sizeof(test_buffer->hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &test_buffer->hash_algo,
                     &data_size);
    test_buffer->hash_size = libspdm_get_hash_size(test_buffer->hash_algo);

    data_size = sizeof(test_buffer->asym_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &test_buffer->asym_algo,
                     &data_size);
    test_buffer->signature_size = libspdm_get_asym_signature_size(test_buffer->asym_algo);

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

    spdm_test_context->test_scratch_buffer_size = offsetof(spdm_challenge_auth_test_buffer_t,
                                                           total_digest_buffer) +
                                                  test_buffer->hash_size * test_buffer->slot_count;

    return true;
}

bool spdm_test_case_challenge_auth_setup_version_any (void *test_context)
{
    return spdm_test_case_challenge_auth_setup_vca_digest (test_context, 0, NULL);
}

bool spdm_test_case_challenge_auth_setup_version_10_11 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_challenge_auth_setup_vca_digest (test_context,
                                                           LIBSPDM_ARRAY_SIZE(
                                                               spdm_version), spdm_version);
}

bool spdm_test_case_challenge_auth_setup_version_12 (void *test_context)
{
    spdm_version_number_t spdm_version[] = {
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT
    };
    return spdm_test_case_challenge_auth_setup_vca_digest (test_context,
                                                           LIBSPDM_ARRAY_SIZE(
                                                               spdm_version), spdm_version);
}

bool spdm_test_case_challenge_auth_setup_version_capabilities (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    spdm_version_number_t spdm_version;
    spdm_challenge_auth_test_buffer_t *test_buffer;

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
                   sizeof(spdm_challenge_auth_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_challenge_auth_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_challenge_auth_test_buffer_t);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &test_buffer->rsp_cap_flags, &data_size);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) ||
        ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0)) {
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

void spdm_test_case_challenge_auth_success_10_12 (void *test_context, uint8_t version,
                                                  uint8_t message_mask)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_challenge_request_t spdm_request;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint8_t cert_chain_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    common_test_result_t test_result;
    spdm_challenge_auth_test_buffer_t *test_buffer;
    uint8_t slot_id;
    uint8_t hash_index;
    uint8_t meas_hash_type_index;
    uint32_t meas_hash_size;
    uint8_t *cert_chain_hash_ptr;
    uint16_t *opaque_length_ptr;
    uint8_t *signature_ptr;
    bool result;
    uint8_t measurement_hash_type[] = {
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
        SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
    };
    common_test_case_id case_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_challenge_auth_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    switch (version) {
    case SPDM_MESSAGE_VERSION_10:
        LIBSPDM_ASSERT ((test_buffer->version == SPDM_MESSAGE_VERSION_10) ||
                        (test_buffer->version == SPDM_MESSAGE_VERSION_11));
        switch (message_mask) {
        case SPDM_MESSAGE_A_MASK_VCA | SPDM_MESSAGE_B_MASK_GET_DIGESTS |
            SPDM_MESSAGE_B_MASK_GET_CERTIFICATE:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B1C1;
            break;
        case SPDM_MESSAGE_A_MASK_VCA:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B2C1;
            break;
        case SPDM_MESSAGE_A_MASK_VCA | SPDM_MESSAGE_B_MASK_GET_DIGESTS:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B3C1;
            break;
        default:
            LIBSPDM_ASSERT(false);
            return;
        }
        break;
    case SPDM_MESSAGE_VERSION_12:
        LIBSPDM_ASSERT (test_buffer->version == SPDM_MESSAGE_VERSION_12);
        switch (message_mask) {
        case SPDM_MESSAGE_A_MASK_VCA | SPDM_MESSAGE_B_MASK_GET_DIGESTS |
            SPDM_MESSAGE_B_MASK_GET_CERTIFICATE:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B1C1;
            break;
        case SPDM_MESSAGE_A_MASK_VCA:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B2C1;
            break;
        case SPDM_MESSAGE_A_MASK_VCA | SPDM_MESSAGE_B_MASK_GET_DIGESTS:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B3C1;
            break;
        case SPDM_MESSAGE_A_MASK_VCA | SPDM_MESSAGE_B_MASK_GET_CERTIFICATE:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B4C1;
            break;
        case SPDM_MESSAGE_B_MASK_GET_DIGESTS | SPDM_MESSAGE_B_MASK_GET_CERTIFICATE:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B1C1;
            break;
        case 0:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B2C1;
            break;
        case SPDM_MESSAGE_B_MASK_GET_DIGESTS:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B3C1;
            break;
        case SPDM_MESSAGE_B_MASK_GET_CERTIFICATE:
            case_id = SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B4C1;
            break;
        default:
            LIBSPDM_ASSERT(false);
            return;
        }
        break;
    default:
        LIBSPDM_ASSERT(false);
        return;
    }

    hash_index = 0;
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((test_buffer->slot_mask & (0x1 << slot_id)) == 0) {
            continue;
        }
        common_test_record_test_message ("test slot - 0x%02x (hash index - 0x%02x)\n", slot_id,
                                         hash_index);

        for (meas_hash_type_index = 0;
             meas_hash_type_index < LIBSPDM_ARRAY_SIZE(measurement_hash_type);
             meas_hash_type_index++) {
            if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) {
                if (measurement_hash_type[meas_hash_type_index] !=
                    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH) {
                    continue;
                }
            }
            common_test_record_test_message ("test meas hash type - 0x%02x\n",
                                             measurement_hash_type[meas_hash_type_index]);

            status = libspdm_init_connection (spdm_context, false);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "init_connection failure");
                continue;
            }

            if ((message_mask & SPDM_MESSAGE_A_MASK_VCA) == 0) {
                status =
                    libspdm_challenge (spdm_context, slot_id,
                                       measurement_hash_type[meas_hash_type_index], NULL, NULL);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    common_test_record_test_assertion (
                        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                        COMMON_TEST_RESULT_NOT_TESTED, "first challenge failure");
                    continue;
                }
            }

            if ((message_mask & SPDM_MESSAGE_B_MASK_GET_DIGESTS) != 0) {
                status = libspdm_get_digest (spdm_context, NULL, NULL);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    common_test_record_test_assertion (
                        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                        COMMON_TEST_RESULT_NOT_TESTED, "get_digest failure");
                    continue;
                }
            }

            if ((message_mask & SPDM_MESSAGE_B_MASK_GET_CERTIFICATE) != 0) {
                cert_chain_buffer_size = sizeof(cert_chain_buffer);
                status = libspdm_get_certificate (spdm_context, slot_id, &cert_chain_buffer_size,
                                                  cert_chain_buffer);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    common_test_record_test_assertion (
                        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                        COMMON_TEST_RESULT_NOT_TESTED, "get_certificate failure");
                    continue;
                }
            }

            libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
            spdm_request.header.spdm_version = test_buffer->version;
            spdm_request.header.request_response_code = SPDM_CHALLENGE;
            spdm_request.header.param1 = slot_id;
            spdm_request.header.param2 = measurement_hash_type[meas_hash_type_index];
            /* ignore spdm_request.nonce */

            spdm_response = (void *)message;
            spdm_response_size = sizeof(message);
            libspdm_zero_mem(message, sizeof(message));
            status = libspdm_send_receive_data(spdm_context, NULL, false,
                                               &spdm_request, sizeof(spdm_request),
                                               spdm_response, &spdm_response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
                return;
            }

            if (measurement_hash_type[meas_hash_type_index] ==
                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH) {
                meas_hash_size = 0;
            } else {
                meas_hash_size = test_buffer->hash_size;
            }
            opaque_length_ptr =
                (void *)((size_t)spdm_response + sizeof(spdm_challenge_auth_response_t) +
                         test_buffer->hash_size + SPDM_NONCE_SIZE +
                         meas_hash_size);
            if (spdm_response_size < sizeof(spdm_challenge_auth_response_t) +
                test_buffer->hash_size + SPDM_NONCE_SIZE +
                meas_hash_size + sizeof(uint16_t) +
                test_buffer->signature_size) {
                test_result = COMMON_TEST_RESULT_FAIL;
            } else {
                if (spdm_response_size < sizeof(spdm_challenge_auth_response_t) +
                    test_buffer->hash_size + SPDM_NONCE_SIZE +
                    meas_hash_size + sizeof(uint16_t) +
                    *opaque_length_ptr + test_buffer->signature_size) {
                    test_result = COMMON_TEST_RESULT_FAIL;
                } else {
                    test_result = COMMON_TEST_RESULT_PASS;
                }
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 1,
                test_result, "response size - %d", spdm_response_size);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }
            cert_chain_hash_ptr =
                (void *)((size_t)spdm_response + sizeof(spdm_challenge_auth_response_t));
            signature_ptr =
                (void *)((size_t)spdm_response + sizeof(spdm_challenge_auth_response_t) +
                         test_buffer->hash_size + SPDM_NONCE_SIZE +
                         meas_hash_size + sizeof(uint16_t) +
                         *opaque_length_ptr);

            if (spdm_response->header.request_response_code == SPDM_CHALLENGE_AUTH) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 2,
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
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 3,
                test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            if ((spdm_response->header.param1 &
                 SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) == slot_id) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 4,
                test_result, "response param1 - 0x%02x", spdm_response->header.param1);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            if ((spdm_response->header.param2 & (1 << slot_id)) != 0) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 5,
                test_result, "response param2 - 0x%02x", spdm_response->header.param2);
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            if (libspdm_const_compare_mem (cert_chain_hash_ptr,
                                           &test_buffer->total_digest_buffer[hash_index *
                                                                             test_buffer->hash_size],
                                           test_buffer->hash_size) == 0) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 6,
                test_result, "response cert chain hash");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }

            status = libspdm_append_message_c(spdm_context, &spdm_request,
                                              sizeof(spdm_request));
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_c failure");
                return;
            }
            status = libspdm_append_message_c(spdm_context, spdm_response,
                                              (size_t)signature_ptr - (size_t)spdm_response);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_c failure");
                return;
            }
            result = libspdm_verify_challenge_auth_signature(
                spdm_context, true, signature_ptr, test_buffer->signature_size);
            if (result) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH, case_id, 7,
                test_result, "response signature");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return;
            }
        }

        hash_index++;
    }
}

void spdm_test_case_challenge_auth_success_10_a1b1c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_10,
                                                 SPDM_MESSAGE_A_MASK_VCA |
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS |
                                                 SPDM_MESSAGE_B_MASK_GET_CERTIFICATE);
}

void spdm_test_case_challenge_auth_success_10_a1b2c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_10,
                                                 SPDM_MESSAGE_A_MASK_VCA);
}

void spdm_test_case_challenge_auth_success_10_a1b3c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_10,
                                                 SPDM_MESSAGE_A_MASK_VCA |
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS);
}

void spdm_test_case_challenge_auth_success_12_a1b1c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_A_MASK_VCA |
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS |
                                                 SPDM_MESSAGE_B_MASK_GET_CERTIFICATE);
}

void spdm_test_case_challenge_auth_success_12_a1b2c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_A_MASK_VCA);
}

void spdm_test_case_challenge_auth_success_12_a1b3c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_A_MASK_VCA |
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS);
}

void spdm_test_case_challenge_auth_success_12_a1b4c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_A_MASK_VCA |
                                                 SPDM_MESSAGE_B_MASK_GET_CERTIFICATE);
}

void spdm_test_case_challenge_auth_success_12_a2b1c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS |
                                                 SPDM_MESSAGE_B_MASK_GET_CERTIFICATE);
}

void spdm_test_case_challenge_auth_success_12_a2b2c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12, 0);
}

void spdm_test_case_challenge_auth_success_12_a2b3c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_B_MASK_GET_DIGESTS);
}

void spdm_test_case_challenge_auth_success_12_a2b4c1 (void *test_context)
{
    spdm_test_case_challenge_auth_success_10_12 (test_context,
                                                 SPDM_MESSAGE_VERSION_12,
                                                 SPDM_MESSAGE_B_MASK_GET_CERTIFICATE);
}

void spdm_test_case_challenge_auth_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_challenge_request_t spdm_request;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_challenge_auth_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_challenge_auth_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_CHALLENGE;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, sizeof(spdm_request),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
                SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, 2,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_challenge_auth_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_challenge_request_t spdm_request;
    spdm_challenge_auth_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_challenge_auth_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_CHALLENGE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
        SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, 1,
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
        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
        SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, 2,
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
        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
        SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, 3,
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
        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
        SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, 4,
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
        SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
        SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_challenge_auth_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_challenge_request_t spdm_request;
    spdm_challenge_request_t spdm_request_new;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_challenge_auth_test_buffer_t *test_buffer;
    size_t index;
    uint8_t slot_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_challenge_auth_test_buffer_t, total_digest_buffer) +
                   test_buffer->hash_size * test_buffer->slot_count);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_CHALLENGE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;

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
            common_test_record_test_message ("test invalid meas_hash_type - 0x%02x\n",
                                             SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH +
                                             1);
            spdm_request_new.header.param2 = SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH +
                                             1;
        } else {
            common_test_record_test_message ("test invalid meas_hash_type - 0x%02x\n",
                                             SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH - 1);
            spdm_request_new.header.param2 = SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH - 1;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, sizeof(spdm_request_new),
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
                SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, 1,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, 2,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, 3,
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
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
            SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_challenge_auth[] = {
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B1C1,
     "spdm_test_case_challenge_auth_success_10_a1b1c1",
     spdm_test_case_challenge_auth_success_10_a1b1c1,
     spdm_test_case_challenge_auth_setup_version_10_11},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B2C1,
     "spdm_test_case_challenge_auth_success_10_a1b2c1",
     spdm_test_case_challenge_auth_success_10_a1b2c1,
     spdm_test_case_challenge_auth_setup_version_10_11},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B3C1,
     "spdm_test_case_challenge_auth_success_10_a1b3c1",
     spdm_test_case_challenge_auth_success_10_a1b3c1,
     spdm_test_case_challenge_auth_setup_version_10_11},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH,
     "spdm_test_case_challenge_auth_version_mismatch",
     spdm_test_case_challenge_auth_version_mismatch,
     spdm_test_case_challenge_auth_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST,
     "spdm_test_case_challenge_auth_unexpected_request",
     spdm_test_case_challenge_auth_unexpected_request,
     spdm_test_case_challenge_auth_setup_version_capabilities},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST,
     "spdm_test_case_challenge_auth_invalid_request",
     spdm_test_case_challenge_auth_invalid_request,
     spdm_test_case_challenge_auth_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B1C1,
     "spdm_test_case_challenge_auth_success_12_a1b1c1",
     spdm_test_case_challenge_auth_success_12_a1b1c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B2C1,
     "spdm_test_case_challenge_auth_success_12_a1b2c1",
     spdm_test_case_challenge_auth_success_12_a1b2c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B3C1,
     "spdm_test_case_challenge_auth_success_12_a1b3c1",
     spdm_test_case_challenge_auth_success_12_a1b3c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B4C1,
     "spdm_test_case_challenge_auth_success_12_a1b4c1",
     spdm_test_case_challenge_auth_success_12_a1b4c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B1C1,
     "spdm_test_case_challenge_auth_success_12_a2b1c1",
     spdm_test_case_challenge_auth_success_12_a2b1c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B2C1,
     "spdm_test_case_challenge_auth_success_12_a2b2c1",
     spdm_test_case_challenge_auth_success_12_a2b2c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B3C1,
     "spdm_test_case_challenge_auth_success_12_a2b3c1",
     spdm_test_case_challenge_auth_success_12_a2b3c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B4C1,
     "spdm_test_case_challenge_auth_success_12_a2b4c1",
     spdm_test_case_challenge_auth_success_12_a2b4c1,
     spdm_test_case_challenge_auth_setup_version_12},
    {COMMON_TEST_ID_END, NULL, NULL},
};
