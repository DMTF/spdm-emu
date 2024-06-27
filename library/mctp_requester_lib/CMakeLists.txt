cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_mctp_requester_lib
    mctp_send_receive.c
    pldm_send_receive.c
    pldm_req_control_get_tid.c
)

add_library(mctp_requester_lib STATIC ${src_mctp_requester_lib})
