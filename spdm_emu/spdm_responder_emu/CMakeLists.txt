cmake_minimum_required(VERSION 3.5)

include_directories(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_responder_emu
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_responder_emu
    spdm_responder_spdm.c
    spdm_responder_session.c
    spdm_responder_pci_doe.c
    spdm_responder_mctp.c
    spdm_responder_tcp.c
    spdm_responder_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
)

set(spdm_responder_emu_LIBRARY
    memlib
    debuglib
    spdm_responder_lib
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
    mctp_responder_lib
    pci_doe_responder_lib
    pci_ide_km_responder_lib
    pci_ide_km_device_lib_sample
    pci_tdisp_responder_lib
    pci_tdisp_device_lib_sample
    cxl_ide_km_responder_lib
    cxl_ide_km_device_lib_sample
    cxl_tsp_responder_lib
    cxl_tsp_device_lib_sample
    platform_lib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    add_executable(spdm_responder_emu
                   ${src_spdm_responder_emu}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_responder_lib>
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
                   $<TARGET_OBJECTS:mctp_responder_lib>
                   $<TARGET_OBJECTS:pci_doe_responder_lib>
                   $<TARGET_OBJECTS:pci_ide_km_responder_lib>
                   $<TARGET_OBJECTS:pci_ide_km_device_lib_sample>
                   $<TARGET_OBJECTS:pci_tdisp_responder_lib>
                   $<TARGET_OBJECTS:pci_tdisp_device_lib_sample>
                   $<TARGET_OBJECTS:cxl_ide_km_responder_lib>
                   $<TARGET_OBJECTS:cxl_ide_km_device_lib_sample>
                   $<TARGET_OBJECTS:cxl_tsp_responder_lib>
                   $<TARGET_OBJECTS:cxl_tsp_device_lib_sample>
                   $<TARGET_OBJECTS:platform_lib>
    )
else()
    add_executable(spdm_responder_emu ${src_spdm_responder_emu})
    target_link_libraries(spdm_responder_emu ${spdm_responder_emu_LIBRARY})
endif()

# Windows DLL path fix for OpenSSL shared library
if(CMAKE_SYSTEM_NAME MATCHES "Windows" AND NOT TOOLCHAIN STREQUAL "NONE")
    if(CRYPTO STREQUAL "openssl")
        # Copy OpenSSL DLL to emu directory for runtime linking
        if(TARGET openssllib)
            add_custom_command(TARGET spdm_responder_emu POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:openssllib>
                $<TARGET_FILE_DIR:spdm_responder_emu>
                COMMENT "Copying OpenSSL DLL to emu directory"
            )
        endif()
    endif()
endif()