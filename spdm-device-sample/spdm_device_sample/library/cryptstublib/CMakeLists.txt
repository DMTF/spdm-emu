cmake_minimum_required(VERSION 3.5)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_compile_options(-Wno-incompatible-pointer-types -Wno-pointer-sign)
    add_compile_options(-Werror)
endif()

include_directories(${SPDM_EMU_DIR}/include
                    ${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

set(src_cryptstublib
    rand.c
    timeclock.c
)

add_library(cryptstublib STATIC ${src_cryptstublib})
