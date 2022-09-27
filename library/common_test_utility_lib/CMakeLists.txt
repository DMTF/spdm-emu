cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${COMMON_TEST_FRAMEWORK_DIR}/include
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_common_test_utility_lib
    common_test_utility_lib.c
)

ADD_LIBRARY(common_test_utility_lib STATIC ${src_common_test_utility_lib})
