cmake_minimum_required(VERSION 3.5)

include_directories(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_${DEVICE}
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_device_attester_sample
    spdm_device_attester_sample.c
    spdm_device_attester_spdm.c
    spdm_device_attester_pci_doe.c
    spdm_device_attester_collection.c
    spdm_device_attester_measurement.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

set(spdm_device_attester_sample_LIBRARY
    memlib
    debuglib_null
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_transport_pcidoe_lib
    spdm_transport_none_lib
    spdm_transport_tcp_lib
    spdm_device_secret_lib_${DEVICE}
    mctp_requester_lib
    pci_doe_requester_lib
    platform_lib
    spdm_responder_conformance_test_lib
    common_test_utility_lib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    add_executable(spdm_device_attester_sample
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
                   $<TARGET_OBJECTS:spdm_transport_tcp_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_${DEVICE}>
                   $<TARGET_OBJECTS:platform_lib>
                   $<TARGET_OBJECTS:spdm_responder_conformance_test_lib>
                   $<TARGET_OBJECTS:common_test_utility_lib>
    )
else()
    add_executable(spdm_device_attester_sample ${src_spdm_device_attester_sample})
    target_link_libraries(spdm_device_attester_sample ${spdm_device_attester_sample_LIBRARY})
endif()
