cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Werror)
endif()

INCLUDE_DIRECTORIES(${SPDM_DEVICE_DIR}/include
                    ${SPDM_EMU_DIR}/include
                    spdm_device_secret_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_device_secret_lib
    lib.c
    cert.c
)

ADD_LIBRARY(spdm_device_secret_lib STATIC ${src_spdm_device_secret_lib})
