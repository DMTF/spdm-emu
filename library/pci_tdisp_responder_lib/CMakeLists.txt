cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_tdisp_responder_lib
    pci_tdisp_dispatch.c
    pci_tdisp_rsp_error.c
    pci_tdisp_rsp_version.c
    pci_tdisp_rsp_capabilities.c
    pci_tdisp_rsp_lock_interface.c
    pci_tdisp_rsp_interface_report.c
    pci_tdisp_rsp_interface_state.c
    pci_tdisp_rsp_start_interface.c
    pci_tdisp_rsp_stop_interface.c
)

add_library(pci_tdisp_responder_lib STATIC ${src_pci_tdisp_responder_lib})
