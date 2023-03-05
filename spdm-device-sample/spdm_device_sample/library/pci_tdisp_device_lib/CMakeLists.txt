cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Werror)
endif()

INCLUDE_DIRECTORIES(${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_tdisp_device_lib
    pci_tdisp_device_context.c
    pci_tdisp_device_version.c
    pci_tdisp_device_capabilities.c
    pci_tdisp_device_lock_interface.c
    pci_tdisp_device_interface_report.c
    pci_tdisp_device_interface_state.c
    pci_tdisp_device_start_interface.c
    pci_tdisp_device_stop_interface.c
)

ADD_LIBRARY(pci_tdisp_device_lib STATIC ${src_pci_tdisp_device_lib})
