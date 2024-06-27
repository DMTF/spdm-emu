cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Werror)
endif()

include_directories(${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_tdisp_device_lib
    pci_tdisp_device_context.c
    pci_tdisp_device_version.c
    pci_tdisp_device_capabilities.c
    pci_tdisp_device_lock_interface.c
    pci_tdisp_device_interface_report.c
    pci_tdisp_device_interface_state.c
    pci_tdisp_device_start_interface.c
    pci_tdisp_device_stop_interface.c
)

add_library(pci_tdisp_device_lib STATIC ${src_pci_tdisp_device_lib})
