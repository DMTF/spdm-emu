cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_cxl_ide_km_requester_lib
    cxl_ide_km_send_receive.c
    cxl_ide_km_req_query.c
    cxl_ide_km_req_key_prog.c
    cxl_ide_km_req_key_set_go.c
    cxl_ide_km_req_key_set_stop.c
    cxl_ide_km_req_get_key.c
)

add_library(cxl_ide_km_requester_lib STATIC ${src_cxl_ide_km_requester_lib})
