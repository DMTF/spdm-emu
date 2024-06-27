cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_ide_km_device_lib_sample
    pci_ide_km_device_context.c
    pci_ide_km_device_query.c
    pci_ide_km_device_key_prog.c
    pci_ide_km_device_key_set_go.c
    pci_ide_km_device_key_set_stop.c
)

add_library(pci_ide_km_device_lib_sample STATIC ${src_pci_ide_km_device_lib_sample})
