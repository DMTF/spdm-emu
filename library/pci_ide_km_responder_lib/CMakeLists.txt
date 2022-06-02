cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_pci_ide_km_responder_lib
    pci_ide_km_dispatch.c
    pci_ide_km_rsp_query.c
    pci_ide_km_rsp_key_prog.c
    pci_ide_km_rsp_key_set_go.c
    pci_ide_km_rsp_key_set_stop.c
)

ADD_LIBRARY(pci_ide_km_responder_lib STATIC ${src_pci_ide_km_responder_lib})
