cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_pci_doe_responder_lib
    pci_doe_dispatch.c
    pci_doe_rsp_discovery.c
    pci_doe_spdm_vendor_dispatch.c
    pci_ide_km_dispatch.c
    pci_ide_km_rsp_query.c
)

ADD_LIBRARY(pci_doe_responder_lib STATIC ${src_pci_doe_responder_lib})
