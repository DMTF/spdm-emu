/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __COMMON_TEST_UTILITY_LIB_H__
#define __COMMON_TEST_UTILITY_LIB_H__

#include "library/spdm_common_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

typedef uint32_t common_test_group_id;
typedef uint32_t common_test_case_id;
typedef uint32_t common_test_assertion_id;

/* This can be used as "end of list" indicator. */
#define COMMON_TEST_ID_END 0
/* This can be used as "test skip" indicator. */
#define COMMON_TEST_ID_SKIP 0xFFFFFFFF

typedef enum {
    COMMON_TEST_RESULT_NOT_TESTED,
    COMMON_TEST_RESULT_PASS,
    COMMON_TEST_RESULT_FAIL,
} common_test_result_t;

typedef void (*common_test_case_func_t) (void *test_context);

/**
 * @return true  setup successfully
 * @return false setup fail
 **/
typedef bool (*common_test_case_setup_func_t) (void *test_context);
typedef void (*common_test_case_teardown_func_t) (void *test_context);

/**
 * @return true  setup successfully
 * @return false setup fail
 **/
typedef bool (*common_test_group_setup_func_t) (void *test_context);
typedef void (*common_test_group_teardown_func_t) (void *test_context);

/**
 *
 +------------+
 | test suite |
 +------------+
 |            +------------+
 +----------->| test group |
 |            +------------+
 |                  |            +------------+
 |                  +----------->| test case  |
 |                  |            +------------+
 |                  |
 |                  |            +------------+
 |                  +----------->| test case  |
 |                               +------------+
 |            +------------+
 +----------->| test group |
 +------------+
 |
 **/

typedef struct {
    uint32_t case_id;
    char                              *case_name;
    common_test_case_func_t case_func;
    common_test_case_setup_func_t case_setup_func;
    common_test_case_teardown_func_t case_teardown_func;
} common_test_case_t;

typedef struct {
    uint32_t group_id;
    char                               *group_name;
    common_test_case_t                 *test_cases;
    common_test_group_setup_func_t group_setup_func;
    common_test_group_teardown_func_t group_teardown_func;
} common_test_group_t;

typedef struct {
    char                *name;
    common_test_group_t *test_groups;
} common_test_suite_t;

/**
 *
 +-------------------+
 | test suite config |
 +-------------------+
 |            +-------------------+
 +----------->| test group config |
 |            +-------------------+
 |                  |            +-------------------+
 |                  +----------->| test case config  |
 |                  |            +-------------------+
 |                  |
 |                  |            +-------------------+
 |                  +----------->| test case config  |
 |                               +-------------------+
 |            +-------------------+
 +----------->| test group config |
 +-------------------+
 |
 | rules:
 |      1) NULL == RUN
 |      2) not-found == SKIP
 |      3) SKIP + RUN == RUN + SKIP == SKIP
 |
 +==========================================+
 | suite |    group   |    case    | ACTION |
 +==========================================+
 |  NULL |     -      |     -      |  RUN   |
 +------------------------------------------+
 | exist |    NULL    |     -      |  RUN   |
 +------------------------------------------+
 | exist | not-found  |     -      |  SKIP  |
 +------------------------------------------+
 | exist | found:SKIP |     -      |  SKIP  |
 +------------------------------------------+
 | exist | found:RUN  |    NULL    |  RUN   |
 +------------------------------------------+
 | exist | found:RUN  | not-found  |  SKIP  |
 +------------------------------------------+
 | exist | found:RUN  | found:SKIP |  SKIP  |
 +------------------------------------------+
 | exist | found:RUN  | found:RUN  |  RUN   |
 +==========================================+
 |
 **/

typedef enum {
    COMMON_TEST_ACTION_RUN,
    COMMON_TEST_ACTION_SKIP,
} common_test_action_t;

typedef struct {
    uint32_t case_id;
    common_test_action_t action;
} common_test_case_config_t;

typedef struct {
    uint32_t group_id;
    common_test_action_t action;
    common_test_case_config_t   *test_case_configs;
} common_test_group_config_t;

typedef struct {
    char                        *config_name;
    common_test_group_config_t  *test_group_configs;
} common_test_suite_config_t;

void common_test_run_test_suite (
    void *test_context,
    const common_test_suite_t *test_suite,
    const common_test_suite_config_t *test_suite_config);

void common_test_record_test_assertion (
    common_test_group_id group_id,
    common_test_case_id case_id,
    common_test_assertion_id assertion_id,
    common_test_result_t test_result,
    const char *message_format,
    ...);

void common_test_record_test_message(const char *message_format, ...);

#endif
