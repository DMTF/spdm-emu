cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_cxl_tsp_requester_lib
    cxl_tsp_send_receive.c
    cxl_tsp_req_get_version.c
    cxl_tsp_req_get_capabilities.c
    cxl_tsp_req_set_configuration.c
    cxl_tsp_req_get_configuration.c
    cxl_tsp_req_get_configuration_report.c
    cxl_tsp_req_lock_configuration.c
    cxl_tsp_req_set_te_state.c
)

add_library(cxl_tsp_requester_lib STATIC ${src_cxl_tsp_requester_lib})
