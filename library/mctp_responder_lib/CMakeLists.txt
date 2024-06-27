cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_mctp_responder_lib
    mctp_dispatch.c
    pldm_dispatch.c
    pldm_rsp_control_get_tid.c
)

add_library(mctp_responder_lib STATIC ${src_mctp_responder_lib})
