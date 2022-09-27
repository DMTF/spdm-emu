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
    uint8_t support_version_bitmask;
} spdm_algorithms_test_buffer_t;
#pragma pack()

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification;
    uint8_t other_params_support;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint8_t reserved2[12];
    uint8_t ext_asym_count;
    uint8_t ext_hash_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} spdm_negotiate_algorithms_request_mine_t;

#pragma pack()

bool spdm_test_case_algorithms_setup_version_capabilities (void *test_context,
                                                           spdm_version_number_t spdm_version)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    spdm_algorithms_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    if (spdm_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, sizeof(spdm_version));
    }

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
                   sizeof(spdm_algorithms_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_algorithms_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_algorithms_test_buffer_t);

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version,
                     &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &test_buffer->rsp_cap_flags, &data_size);

    test_buffer->support_version_bitmask = 0;

    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_algorithms_test_buffer_t);

    return true;
}

bool spdm_test_case_algorithms_setup_version_10 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
                                                                 SPDM_MESSAGE_VERSION_10 <<
        SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_algorithms_setup_version_11 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
                                                                 SPDM_MESSAGE_VERSION_11 <<
        SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_algorithms_setup_version_12 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
                                                                 SPDM_MESSAGE_VERSION_12 <<
        SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_algorithms_setup_version_any (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context, 0);
}

bool spdm_test_case_algorithms_setup_version_only (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;
    size_t data_size;
    spdm_algorithms_test_buffer_t *test_buffer;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >=
                   sizeof(spdm_algorithms_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_algorithms_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_algorithms_test_buffer_t);

    version_number_entry_count = LIBSPDM_MAX_VERSION_COUNT;
    status = libspdm_get_version (spdm_context, &version_number_entry_count, version_number_entry);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version,
                     &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &test_buffer->rsp_cap_flags, &data_size);

    return true;
}

void spdm_test_case_algorithms_success_10 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t algo;
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
    spdm_request.header.param1 = 0;
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_algorithms_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_ALGORITHMS) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if ((spdm_response->length <= spdm_response_size) &&
        (spdm_response->length == sizeof(spdm_algorithms_response_t) +
         spdm_response->ext_asym_sel_count * sizeof(spdm_extended_algorithm_t) +
         spdm_response->ext_hash_sel_count * sizeof(spdm_extended_algorithm_t))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 4,
        test_result, "response length - 0x%04x", spdm_response->length);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_asym_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 5,
        test_result, "response ext_asym_sel_count - 0x%02x", spdm_response->ext_asym_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_hash_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 6,
        test_result, "response ext_hash_sel_count - 0x%02x", spdm_response->ext_hash_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    algo = spdm_test_get_one_bit (spdm_response->measurement_specification_sel,
                                  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
    if (algo != 0xFFFFFFFF) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 7,
        test_result, "response measurement_specification_sel - 0x%02x",
        spdm_response->measurement_specification_sel);

    algo = spdm_test_get_one_bit (spdm_response->measurement_hash_algo,
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) != 0) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ==
                0) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 8,
        test_result, "response measurement_hash_algo - 0x%08x",
        spdm_response->measurement_hash_algo);

    algo = spdm_test_get_one_bit (spdm_response->base_asym_sel,
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 9,
        test_result, "response base_asym_sel - 0x%08x", spdm_response->base_asym_sel);

    algo = spdm_test_get_one_bit (spdm_response->base_hash_sel,
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 10,
        test_result, "response base_hash_sel - 0x%08x", spdm_response->base_hash_sel);
}

void spdm_test_case_algorithms_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n",
                                         mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
        spdm_request.header.param1 = 0;
        spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
        spdm_request.header.param2 = 0;
        spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_request.ext_asym_count = 0;
        spdm_request.ext_hash_count = 0;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, spdm_request.length,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 2,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_algorithms_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    size_t spdm_request_size;
    spdm_algorithms_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    uint8_t version;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    /* libspdm_check_request_version_compability will set the connection_info version
     * This case receives a NEGOTIATE_ALGORITHMS before GET_CAPABILITIES, the conection_info version is 0*/
    version = 0;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request_size = sizeof(spdm_request);
    } else {
        spdm_request_size = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = version;
    spdm_request.length = (uint16_t)spdm_request_size;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request.header.param1 = 4;
    } else {
        spdm_request.header.param1 = 0;
    }
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    }
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_asym_algo |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_hash_algo |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    }
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[0].alg_supported |= SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    }
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[1].alg_supported |=
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    }
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[2].alg_supported |=
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
        SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, 1,
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
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
        SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
        SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, 3,
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
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
        SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, 4,
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
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
        SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_algorithms_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_negotiate_algorithms_request_mine_t spdm_request_new;
    size_t spdm_request_size;
    spdm_algorithms_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request_size = sizeof(spdm_request);
    } else {
        spdm_request_size = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.length = (uint16_t)spdm_request_size;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request.header.param1 = 4;
    } else {
        spdm_request.header.param1 = 0;
    }
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    }
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_asym_algo |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_hash_algo |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    }
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[0].alg_supported |= SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    }
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[1].alg_supported |=
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    }
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[2].alg_supported |=
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

    for (index = 0; index < 6; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request,
                          sizeof(spdm_request));
        switch (index) {
        case 0:
            spdm_request_new.length += SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_LENGTH_VERSION_11 + 1;
            common_test_record_test_message ("test length - 0x%04x\n", spdm_request_new.length);
            break;
        case 1:
            spdm_request_new.ext_asym_count = 21;
            common_test_record_test_message ("test ext_asym_count - 0x%02x\n",
                                             spdm_request_new.ext_asym_count);
            break;
        case 2:
            spdm_request_new.ext_hash_count = 21;
            common_test_record_test_message ("test ext_hash_count - 0x%02x\n",
                                             spdm_request_new.ext_hash_count);
            break;
        case 3:
            if (test_buffer->version < SPDM_MESSAGE_VERSION_11) {
                continue;
            }
            spdm_request_new.struct_table[0].alg_count = 0x10;
            common_test_record_test_message ("test alg_count - 0x%02x\n",
                                             spdm_request_new.struct_table[0].alg_count);
            break;
        case 4:
            if (test_buffer->version < SPDM_MESSAGE_VERSION_11) {
                continue;
            }
            spdm_request_new.struct_table[0].alg_count = 0x30;
            common_test_record_test_message ("test alg_count - 0x%02x\n",
                                             spdm_request_new.struct_table[0].alg_count);
            break;
        case 5:
            if (test_buffer->version < SPDM_MESSAGE_VERSION_11) {
                continue;
            }
            spdm_request_new.struct_table[0].alg_count = 0x0F;
            spdm_request_new.struct_table[1].alg_count = 0x0F;
            spdm_request_new.struct_table[2].alg_count = 0x0F;
            spdm_request_new.struct_table[3].alg_count = 0x0F;
            common_test_record_test_message ("test multiple alg_count - 0x%02x\n",
                                             spdm_request_new.struct_table[0].alg_count);
            break;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, spdm_request_new.length,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, 1,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, 2,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, 3,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_algorithms_success_11 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t algo;
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    bool dhe_named_group_is_found;
    bool aead_cipher_suite_is_found;
    bool req_base_asym_alg_is_found;
    bool key_schedule_is_found;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t req_base_asym_alg;
    uint16_t key_schedule;
    size_t index;
    uint8_t ext_alg_count;

    dhe_named_group = 0;
    aead_cipher_suite = 0;
    req_base_asym_alg = 0;
    key_schedule = 0;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.length = sizeof(spdm_request);
    spdm_request.header.param1 = 4;
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_algorithms_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_ALGORITHMS) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_11) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if ((spdm_response->length <= spdm_response_size) &&
        (spdm_response->length == sizeof(spdm_algorithms_response_t) +
         spdm_response->ext_asym_sel_count * sizeof(spdm_extended_algorithm_t) +
         spdm_response->ext_hash_sel_count * sizeof(spdm_extended_algorithm_t) +
         spdm_response->header.param1 * sizeof(spdm_negotiate_algorithms_common_struct_table_t))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 4,
        test_result, "response length - 0x%04x", spdm_response->length);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_asym_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 5,
        test_result, "response ext_asym_sel_count - 0x%02x", spdm_response->ext_asym_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_hash_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 6,
        test_result, "response ext_hash_sel_count - 0x%02x", spdm_response->ext_hash_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    algo = spdm_test_get_one_bit (spdm_response->measurement_specification_sel,
                                  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
    if (algo != 0xFFFFFFFF) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 7,
        test_result, "response measurement_specification_sel - 0x%02x",
        spdm_response->measurement_specification_sel);

    algo = spdm_test_get_one_bit (spdm_response->measurement_hash_algo,
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) != 0) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ==
                0) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 8,
        test_result, "response measurement_hash_algo - 0x%08x",
        spdm_response->measurement_hash_algo);

    algo = spdm_test_get_one_bit (spdm_response->base_asym_sel,
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 9,
        test_result, "response base_asym_sel - 0x%08x", spdm_response->base_asym_sel);

    algo = spdm_test_get_one_bit (spdm_response->base_hash_sel,
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 10,
        test_result, "response base_hash_sel - 0x%08x", spdm_response->base_hash_sel);

    if (spdm_response->header.param1 <= 4) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);

    dhe_named_group_is_found = false;
    aead_cipher_suite_is_found = false;
    req_base_asym_alg_is_found = false;
    key_schedule_is_found = false;
    struct_table = (void *)((size_t)spdm_response +
                            sizeof(spdm_algorithms_response_t) +
                            sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
                            sizeof(uint32_t) * spdm_response->ext_hash_sel_count);
    for (index = 0; index < spdm_response->header.param1; index++) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            if (dhe_named_group_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
                    test_result, "response dup dhe_named_group - 0x%02x", struct_table->alg_type);
            }
            dhe_named_group_is_found = true;
            dhe_named_group = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            if (aead_cipher_suite_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
                    test_result, "response dup aead_cipher_suite - 0x%02x", struct_table->alg_type);
            }
            aead_cipher_suite_is_found = true;
            aead_cipher_suite = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            if (req_base_asym_alg_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
                    test_result, "response dup req_base_asym_alg - 0x%02x", struct_table->alg_type);
            }
            req_base_asym_alg_is_found = true;
            req_base_asym_alg = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            if (key_schedule_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
                    test_result, "response dup key_schedule - 0x%02x", struct_table->alg_type);
            }
            key_schedule_is_found = true;
            key_schedule = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH);
            break;
        default:
            test_result = COMMON_TEST_RESULT_FAIL;
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 11,
                test_result, "response unknown alg_type - 0x%02x", struct_table->alg_type);
            break;
        }
        if (struct_table->alg_count == 0x20) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11,
            12,
            test_result, "response alg_count - 0x%02x", struct_table->alg_count);
        ext_alg_count = struct_table->alg_count & 0xF;
        struct_table =
            (void *)((size_t)struct_table +
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                     sizeof(uint32_t) * ext_alg_count);
    }

    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) &&
        ((dhe_named_group != 0xFFFF) && (dhe_named_group != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                0) &&
               (dhe_named_group == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 13,
        test_result, "response dhe_named_group - 0x%04x", dhe_named_group);

    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) != 0)) &&
        ((aead_cipher_suite != 0xFFFF) && (aead_cipher_suite != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) ==
                 0)) &&
               (aead_cipher_suite == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 14,
        test_result, "response aead_cipher_suite - 0x%04x", aead_cipher_suite);

    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) != 0) &&
        ((req_base_asym_alg != 0xFFFF) && (req_base_asym_alg != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) ==
                0) &&
               (req_base_asym_alg == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 15,
        test_result, "response req_base_asym_alg - 0x%04x", req_base_asym_alg);

    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) != 0)) &&
        ((key_schedule != 0xFFFF) && (key_schedule != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) ==
                 0)) &&
               (key_schedule == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, 16,
        test_result, "response key_schedule - 0x%04x", key_schedule);
}

void spdm_test_case_algorithms_success_12 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t algo;
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    bool dhe_named_group_is_found;
    bool aead_cipher_suite_is_found;
    bool req_base_asym_alg_is_found;
    bool key_schedule_is_found;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t req_base_asym_alg;
    uint16_t key_schedule;
    size_t index;
    uint8_t ext_alg_count;

    dhe_named_group = 0;
    aead_cipher_suite = 0;
    req_base_asym_alg = 0;
    key_schedule = 0;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.length = sizeof(spdm_request);
    spdm_request.header.param1 = 4;
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
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
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
                                                 |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return;
    }

    if (spdm_response_size >= sizeof(spdm_algorithms_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.request_response_code == SPDM_ALGORITHMS) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_12) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if ((spdm_response->length <= spdm_response_size) &&
        (spdm_response->length == sizeof(spdm_algorithms_response_t) +
         spdm_response->ext_asym_sel_count * sizeof(spdm_extended_algorithm_t) +
         spdm_response->ext_hash_sel_count * sizeof(spdm_extended_algorithm_t) +
         spdm_response->header.param1 * sizeof(spdm_negotiate_algorithms_common_struct_table_t))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 4,
        test_result, "response length - 0x%04x", spdm_response->length);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_asym_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 5,
        test_result, "response ext_asym_sel_count - 0x%02x", spdm_response->ext_asym_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    if (spdm_response->ext_hash_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 6,
        test_result, "response ext_hash_sel_count - 0x%02x", spdm_response->ext_hash_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return;
    }

    algo = spdm_test_get_one_bit (spdm_response->measurement_specification_sel,
                                  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
    if (algo != 0xFFFFFFFF) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 7,
        test_result, "response measurement_specification_sel - 0x%02x",
        spdm_response->measurement_specification_sel);

    algo = spdm_test_get_one_bit (spdm_response->measurement_hash_algo,
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) != 0) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ==
                0) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 8,
        test_result, "response measurement_hash_algo - 0x%08x",
        spdm_response->measurement_hash_algo);

    algo = spdm_test_get_one_bit (spdm_response->base_asym_sel,
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
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
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 9,
        test_result, "response base_asym_sel - 0x%08x", spdm_response->base_asym_sel);

    algo = spdm_test_get_one_bit (spdm_response->base_hash_sel,
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256);
    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ==
                 0)) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 10,
        test_result, "response base_hash_sel - 0x%08x", spdm_response->base_hash_sel);

    if (spdm_response->header.param1 <= 4) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);

    dhe_named_group_is_found = false;
    aead_cipher_suite_is_found = false;
    req_base_asym_alg_is_found = false;
    key_schedule_is_found = false;
    struct_table = (void *)((size_t)spdm_response +
                            sizeof(spdm_algorithms_response_t) +
                            sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
                            sizeof(uint32_t) * spdm_response->ext_hash_sel_count);
    for (index = 0; index < spdm_response->header.param1; index++) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            if (dhe_named_group_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
                    test_result, "response dup dhe_named_group - 0x%02x", struct_table->alg_type);
            }
            dhe_named_group_is_found = true;
            dhe_named_group = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
                                                               SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            if (aead_cipher_suite_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
                    test_result, "response dup aead_cipher_suite - 0x%02x", struct_table->alg_type);
            }
            aead_cipher_suite_is_found = true;
            aead_cipher_suite = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 |
                                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            if (req_base_asym_alg_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
                    test_result, "response dup req_base_asym_alg - 0x%02x", struct_table->alg_type);
            }
            req_base_asym_alg_is_found = true;
            req_base_asym_alg = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
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
                                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            if (key_schedule_is_found) {
                test_result = COMMON_TEST_RESULT_FAIL;
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                    SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
                    test_result, "response dup key_schedule - 0x%02x", struct_table->alg_type);
            }
            key_schedule_is_found = true;
            key_schedule = (uint16_t)spdm_test_get_one_bit (struct_table->alg_supported,
                                                            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH);
            break;
        default:
            test_result = COMMON_TEST_RESULT_FAIL;
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 11,
                test_result, "response unknown alg_type - 0x%02x", struct_table->alg_type);
            break;
        }
        if (struct_table->alg_count == 0x20) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12,
            12,
            test_result, "response alg_count - 0x%02x", struct_table->alg_count);
        ext_alg_count = struct_table->alg_count & 0xF;
        struct_table =
            (void *)((size_t)struct_table +
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                     sizeof(uint32_t) * ext_alg_count);
    }

    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) &&
        ((dhe_named_group != 0xFFFF) && (dhe_named_group != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                0) &&
               (dhe_named_group == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 13,
        test_result, "response dhe_named_group - 0x%04x", dhe_named_group);

    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) != 0)) &&
        ((aead_cipher_suite != 0xFFFF) && (aead_cipher_suite != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) ==
                 0)) &&
               (aead_cipher_suite == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 14,
        test_result, "response aead_cipher_suite - 0x%04x", aead_cipher_suite);

    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) != 0) &&
        ((req_base_asym_alg != 0xFFFF) && (req_base_asym_alg != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) ==
                0) &&
               (req_base_asym_alg == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 15,
        test_result, "response req_base_asym_alg - 0x%04x", req_base_asym_alg);

    if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) ||
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) != 0)) &&
        ((key_schedule != 0xFFFF) && (key_schedule != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ==
                 0) &&
                ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) ==
                 0)) &&
               (key_schedule == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, 16,
        test_result, "response key_schedule - 0x%04x", key_schedule);

    spdm_response->other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0) ||
        ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) != 0)) {
        if (spdm_response->other_params_support == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12,
            17,
            test_result, "response other_params_support - 0x%02x",
            spdm_response->other_params_support);
    }
}

void spdm_test_case_algorithms_unexpected_non_identical (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_negotiate_algorithms_request_mine_t spdm_request_new;
    size_t spdm_request_size;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_algorithms_test_buffer_t *test_buffer;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    size_t index;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t req_base_asym_alg;
    uint8_t ext_alg_count;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT (spdm_test_context->test_scratch_buffer_size ==
                    sizeof(spdm_algorithms_test_buffer_t));

    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request_size = sizeof(spdm_request);
    } else {
        spdm_request_size = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.length = (uint16_t)spdm_request_size;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request.header.param1 = 4;
    } else {
        spdm_request.header.param1 = 0;
    }
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    }
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_asym_algo |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.base_hash_algo |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    }
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[0].alg_supported |= SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    }
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[1].alg_supported |=
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    }
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    if (test_buffer->version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.struct_table[2].alg_supported |=
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    }
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "First send/receive failure");
        return;
    }
    if (spdm_response->header.request_response_code != SPDM_ALGORITHMS) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL,
            COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "First NEGOTIATE_ALGORITHMS failure");
        return;
    }

    base_asym_sel = spdm_response->base_asym_sel;
    base_hash_sel = spdm_response->base_hash_sel;

    dhe_named_group = 0;
    aead_cipher_suite = 0;
    req_base_asym_alg = 0;
    struct_table = (void *)((size_t)spdm_response +
                            sizeof(spdm_algorithms_response_t) +
                            sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
                            sizeof(uint32_t) * spdm_response->ext_hash_sel_count);
    for (index = 0; index < spdm_response->header.param1; index++) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            dhe_named_group = struct_table->alg_supported;
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            aead_cipher_suite = struct_table->alg_supported;
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            req_base_asym_alg = struct_table->alg_supported;
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        default:
            break;
        }
        ext_alg_count = struct_table->alg_count & 0xF;
        struct_table =
            (void *)((size_t)struct_table +
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                     sizeof(uint32_t) * ext_alg_count);
    }

    for (index = 0; index < 3; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request,
                          sizeof(spdm_request));
        switch (index) {
        case 0:
            spdm_request_new.header.param2 = 1;
            common_test_record_test_message ("test param2 - 1\n");
            break;
        case 1:
            spdm_request_new.base_asym_algo = base_asym_sel;
            spdm_request_new.base_hash_algo = base_hash_sel;
            common_test_record_test_message (
                "test base_asym_algo - 0x%08x, base_hash_algo - 0x%08x\n", base_asym_sel,
                base_hash_sel);
            break;
        case 2:
            if (test_buffer->version < SPDM_MESSAGE_VERSION_11) {
                continue;
            }
            spdm_request_new.struct_table[0].alg_supported = dhe_named_group;
            spdm_request_new.struct_table[1].alg_supported = aead_cipher_suite;
            spdm_request_new.struct_table[2].alg_supported = req_base_asym_alg;
            common_test_record_test_message (
                "test dhe_named_group - 0x%04x, aead_cipher_suite - 0x%04x, req_base_asym_alg - 0x%04x\n",
                dhe_named_group, aead_cipher_suite, req_base_asym_alg);
            break;
        default:
            break;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, spdm_request_new.length,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL,
                COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "Second send/receive failure");
            continue;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, 1,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, 2,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.param1 == SPDM_ERROR_CODE_UNEXPECTED_REQUEST) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue;
        }

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
            SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_algorithms[] = {
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, "spdm_test_case_algorithms_success_10",
     spdm_test_case_algorithms_success_10, spdm_test_case_algorithms_setup_version_10},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH,
     "spdm_test_case_algorithms_version_mismatch", spdm_test_case_algorithms_version_mismatch,
     spdm_test_case_algorithms_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST,
     "spdm_test_case_algorithms_unexpected_request",
     spdm_test_case_algorithms_unexpected_request, spdm_test_case_algorithms_setup_version_only},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST,
     "spdm_test_case_algorithms_invalid_request", spdm_test_case_algorithms_invalid_request,
     spdm_test_case_algorithms_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, "spdm_test_case_algorithms_success_11",
     spdm_test_case_algorithms_success_11, spdm_test_case_algorithms_setup_version_11},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, "spdm_test_case_algorithms_success_12",
     spdm_test_case_algorithms_success_12, spdm_test_case_algorithms_setup_version_12},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL,
     "spdm_test_case_algorithms_unexpected_non_identical",
     spdm_test_case_algorithms_unexpected_non_identical,
     spdm_test_case_algorithms_setup_version_any},
    {COMMON_TEST_ID_END, NULL, NULL},
};
