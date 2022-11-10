cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_cxl_ide_km_device_lib_sample
    cxl_ide_km_device_context.c
    cxl_ide_km_device_query.c
    cxl_ide_km_device_key_prog.c
    cxl_ide_km_device_key_set_go.c
    cxl_ide_km_device_key_set_stop.c
    cxl_ide_km_device_get_key.c
)

ADD_LIBRARY(cxl_ide_km_device_lib_sample STATIC ${src_cxl_ide_km_device_lib_sample})
