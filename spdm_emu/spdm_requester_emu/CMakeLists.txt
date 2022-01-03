cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_spdm_requester_emu
    spdm_requester_spdm.c
    spdm_requester_authentication.c
    spdm_requester_measurement.c
    spdm_requester_session.c
    spdm_requester_pci_doe.c
    spdm_requester_mctp.c
    spdm_requester_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

SET(spdm_requester_emu_LIBRARY
    memlib
    debuglib
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
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(spdm_requester_emu
                   ${src_spdm_requester_emu}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
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
    )
else()
    ADD_EXECUTABLE(spdm_requester_emu ${src_spdm_requester_emu})
    TARGET_LINK_LIBRARIES(spdm_requester_emu ${spdm_requester_emu_LIBRARY})
endif()
