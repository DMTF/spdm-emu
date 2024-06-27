cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_tdisp_device_lib_sample
    pci_tdisp_device_context.c
    pci_tdisp_device_version.c
    pci_tdisp_device_capabilities.c
    pci_tdisp_device_lock_interface.c
    pci_tdisp_device_interface_report.c
    pci_tdisp_device_interface_state.c
    pci_tdisp_device_start_interface.c
    pci_tdisp_device_stop_interface.c
)

add_library(pci_tdisp_device_lib_sample STATIC ${src_pci_tdisp_device_lib_sample})
