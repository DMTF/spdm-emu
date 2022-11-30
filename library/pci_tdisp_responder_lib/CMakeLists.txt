cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_tdisp_responder_lib
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

ADD_LIBRARY(pci_tdisp_responder_lib STATIC ${src_pci_tdisp_responder_lib})
