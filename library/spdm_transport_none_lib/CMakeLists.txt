cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_spdm_transport_none_lib
    common.c
    none.c
)

add_library(spdm_transport_none_lib STATIC ${src_spdm_transport_none_lib})
