cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${COMMON_TEST_FRAMEWORK_DIR}/include
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_spdm_responder_conformance_test_lib
    spdm_responder_test.c
    spdm_responder_test_1_version.c
    spdm_responder_test_2_capabilities.c
    spdm_responder_test_3_algorithms.c
    spdm_responder_test_4_digests.c
    spdm_responder_test_5_certificate.c
    spdm_responder_test_6_challenge_auth.c
    spdm_responder_test_7_measurements.c
    spdm_responder_test_8_key_exchange_rsp.c
    spdm_responder_test_9_finish_rsp.c
    spdm_responder_test_12_heartbeat_ack.c
    spdm_responder_test_13_key_update_ack.c
    spdm_responder_test_16_end_session_ack.c
    spdm_responder_test_support.c
)

ADD_LIBRARY(spdm_responder_conformance_test_lib STATIC ${src_spdm_responder_conformance_test_lib})
