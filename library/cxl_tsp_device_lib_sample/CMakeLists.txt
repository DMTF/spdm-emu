cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_cxl_tsp_device_lib_sample
    cxl_tsp_device_context.c
    cxl_tsp_device_get_version.c
    cxl_tsp_device_get_capabilities.c
    cxl_tsp_device_set_configuration.c
    cxl_tsp_device_get_configuration.c
    cxl_tsp_device_get_configuration_report.c
    cxl_tsp_device_lock_configuration.c
)

add_library(cxl_tsp_device_lib_sample STATIC ${src_cxl_tsp_device_lib_sample})
