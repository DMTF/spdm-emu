cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_cxl_tsp_responder_lib
    cxl_tsp_dispatch.c
    cxl_tsp_rsp_get_version.c
    cxl_tsp_rsp_get_capabilities.c
    cxl_tsp_rsp_set_configuration.c
    cxl_tsp_rsp_get_configuration.c
    cxl_tsp_rsp_get_configuration_report.c
    cxl_tsp_rsp_lock_configuration.c
    cxl_tsp_rsp_set_te_state.c
    cxl_tsp_rsp_error.c
)

add_library(cxl_tsp_responder_lib STATIC ${src_cxl_tsp_responder_lib})
