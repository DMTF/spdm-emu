cmake_minimum_required(VERSION 3.5)

include_directories(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_requester_emu
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_requester_emu
    spdm_requester_spdm.c
    spdm_requester_authentication.c
    spdm_requester_endpoint_info.c
    spdm_requester_measurement.c
    spdm_requester_key_pair_info.c
    spdm_requester_session.c
    spdm_requester_pci_doe.c
    spdm_requester_mctp.c
    spdm_requester_tcp.c
    spdm_requester_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

set(spdm_requester_emu_LIBRARY
    memlib
    debuglib
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
    spdm_transport_tcp_lib
    spdm_transport_none_lib
    spdm_device_secret_lib_sample
    mctp_requester_lib
    pci_doe_requester_lib
    pci_ide_km_requester_lib
    pci_tdisp_requester_lib
    cxl_ide_km_requester_lib
    cxl_tsp_requester_lib
    platform_lib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    add_executable(spdm_requester_emu
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
                   $<TARGET_OBJECTS:spdm_transport_tcp_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
                   $<TARGET_OBJECTS:mctp_requester_lib>
                   $<TARGET_OBJECTS:pci_doe_requester_lib>
                   $<TARGET_OBJECTS:pci_ide_km_requester_lib>
                   $<TARGET_OBJECTS:pci_tdisp_requester_lib>
                   $<TARGET_OBJECTS:cxl_ide_km_requester_lib>
                   $<TARGET_OBJECTS:cxl_tsp_requester_lib>
                   $<TARGET_OBJECTS:platform_lib>
    )
else()
    add_executable(spdm_requester_emu ${src_spdm_requester_emu})
    target_link_libraries(spdm_requester_emu ${spdm_requester_emu_LIBRARY})
endif()
