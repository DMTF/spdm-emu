cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_EMU_DIR}/include
)

SET(src_spdm_transport_none_lib
    common.c
    none.c
)

ADD_LIBRARY(spdm_transport_none_lib STATIC ${src_spdm_transport_none_lib})
