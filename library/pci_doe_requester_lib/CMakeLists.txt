cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_doe_requester_lib
    pci_doe_req_discovery.c
    pci_doe_spdm_vendor_send_receive.c
)

add_library(pci_doe_requester_lib STATIC ${src_pci_doe_requester_lib})
