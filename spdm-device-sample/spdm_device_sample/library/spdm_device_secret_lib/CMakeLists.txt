cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Werror)
endif()

include_directories(${SPDM_DEVICE_DIR}/include
                    ${SPDM_EMU_DIR}/include
                    spdm_device_secret_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_device_secret_lib
    lib.c
    cert.c
)

add_library(spdm_device_secret_lib STATIC ${src_spdm_device_secret_lib})
