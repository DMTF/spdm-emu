cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Werror)
endif()

INCLUDE_DIRECTORIES(${SPDM_EMU_DIR}/include
                    ${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_platform_lib
    time.c
    watchdog.c
)

ADD_LIBRARY(platform_lib STATIC ${src_platform_lib})
