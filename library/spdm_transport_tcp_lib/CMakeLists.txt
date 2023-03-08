cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

SET(src_spdm_transport_tcp_lib
    libspdm_tcp_common.c
    libspdm_tcp_tcp.c
)

ADD_LIBRARY(spdm_transport_tcp_lib STATIC ${src_spdm_transport_tcp_lib})
