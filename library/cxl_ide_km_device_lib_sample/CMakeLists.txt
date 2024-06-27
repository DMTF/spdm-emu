cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_cxl_ide_km_device_lib_sample
    cxl_ide_km_device_context.c
    cxl_ide_km_device_query.c
    cxl_ide_km_device_key_prog.c
    cxl_ide_km_device_key_set_go.c
    cxl_ide_km_device_key_set_stop.c
    cxl_ide_km_device_get_key.c
)

add_library(cxl_ide_km_device_lib_sample STATIC ${src_cxl_ide_km_device_lib_sample})
