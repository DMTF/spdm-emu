cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_ide_km_responder_lib
    pci_ide_km_dispatch.c
    pci_ide_km_rsp_query.c
    pci_ide_km_rsp_key_prog.c
    pci_ide_km_rsp_key_set_go.c
    pci_ide_km_rsp_key_set_stop.c
)

add_library(pci_ide_km_responder_lib STATIC ${src_pci_ide_km_responder_lib})
