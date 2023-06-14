cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

SET(src_pci_doe_responder_lib
    pci_doe_dispatch.c
    pci_doe_spdm_vendor_dispatch.c
)

ADD_LIBRARY(pci_doe_responder_lib STATIC ${src_pci_doe_responder_lib})
