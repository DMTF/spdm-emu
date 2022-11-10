cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_doe_requester_lib
    pci_doe_req_discovery.c
    pci_doe_spdm_vendor_send_receive.c
)

ADD_LIBRARY(pci_doe_requester_lib STATIC ${src_pci_doe_requester_lib})
