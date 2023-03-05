cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Werror)
endif()

INCLUDE_DIRECTORIES(${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_ide_km_device_lib
    pci_ide_km_device_context.c
    pci_ide_km_device_query.c
    pci_ide_km_device_key_prog.c
    pci_ide_km_device_key_set_go.c
    pci_ide_km_device_key_set_stop.c
)

ADD_LIBRARY(pci_ide_km_device_lib STATIC ${src_pci_ide_km_device_lib})
