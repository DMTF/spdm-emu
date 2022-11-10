cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_mctp_responder_lib
    mctp_dispatch.c
    pldm_dispatch.c
    pldm_rsp_control_get_tid.c
)

ADD_LIBRARY(mctp_responder_lib STATIC ${src_mctp_responder_lib})
