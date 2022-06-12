cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_responder_test_client
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${SPDM_RESPONDER_VALIDATOR_DIR}/include
                    ${COMMON_TEST_FRAMEWORK_DIR}/include
)

SET(src_spdm_device_validator_sample
    spdm_device_validator_sample.c
    spdm_device_validator_config.c
    spdm_device_validator_spdm.c
    spdm_device_validator_pci_doe.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

SET(spdm_device_validator_sample_LIBRARY
    memlib
    debuglib_null
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_transport_pcidoe_lib
    spdm_transport_none_lib
    spdm_device_secret_lib_sample
    mctp_requester_lib
    pci_doe_requester_lib
    platform_lib
    spdm_responder_conformance_test_lib
    common_test_utility_lib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(spdm_device_validator_sample
                   ${src_spdm_responder_test_client}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib_null>
                   $<TARGET_OBJECTS:spdm_requester_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_mctp_lib>
                   $<TARGET_OBJECTS:spdm_transport_pcidoe_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
                   $<TARGET_OBJECTS:platform_lib>
                   $<TARGET_OBJECTS:spdm_responder_conformance_test_lib>
                   $<TARGET_OBJECTS:common_test_utility_lib>
    )
else()
    ADD_EXECUTABLE(spdm_device_validator_sample ${src_spdm_device_validator_sample})
    TARGET_LINK_LIBRARIES(spdm_device_validator_sample ${spdm_device_validator_sample_LIBRARY})
endif()
