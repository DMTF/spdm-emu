cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_doe_responder_lib
    pci_doe_dispatch.c
    pci_doe_spdm_vendor_dispatch.c
)

add_library(pci_doe_responder_lib STATIC ${src_pci_doe_responder_lib})
