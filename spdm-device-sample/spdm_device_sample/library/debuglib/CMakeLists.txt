cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Werror)
endif()

include_directories(${SPDM_EMU_DIR}/include
                    ${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

set(src_debuglib
    debuglib.c
)

add_library(debuglib STATIC ${src_debuglib})
