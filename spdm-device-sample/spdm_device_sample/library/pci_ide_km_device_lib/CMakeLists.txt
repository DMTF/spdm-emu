cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Werror)
endif()

include_directories(${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_ide_km_device_lib
    pci_ide_km_device_context.c
    pci_ide_km_device_query.c
    pci_ide_km_device_key_prog.c
    pci_ide_km_device_key_set_go.c
    pci_ide_km_device_key_set_stop.c
)

add_library(pci_ide_km_device_lib STATIC ${src_pci_ide_km_device_lib})
