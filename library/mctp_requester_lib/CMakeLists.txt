cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_mctp_requester_lib
    mctp_send_receive.c
    pldm_send_receive.c
    pldm_req_control_get_tid.c
)

ADD_LIBRARY(mctp_requester_lib STATIC ${src_mctp_requester_lib})
