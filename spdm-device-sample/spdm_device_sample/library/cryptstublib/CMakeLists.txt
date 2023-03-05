cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
    ADD_COMPILE_OPTIONS(-Werror)
endif()

INCLUDE_DIRECTORIES(${SPDM_EMU_DIR}/include
                    ${SPDM_DEVICE_DIR}/include
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_cryptstublib
    rand.c
    timeclock.c
)

ADD_LIBRARY(cryptstublib STATIC ${src_cryptstublib})
