cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_tdisp_requester_lib
    pci_tdisp_send_receive.c
    pci_tdisp_req_get_version.c
    pci_tdisp_req_get_capabilities.c
    pci_tdisp_req_lock_interface.c
    pci_tdisp_req_get_interface_report.c
    pci_tdisp_req_get_interface_state.c
    pci_tdisp_req_start_interface.c
    pci_tdisp_req_stop_interface.c
)

ADD_LIBRARY(pci_tdisp_requester_lib STATIC ${src_pci_tdisp_requester_lib})
