/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "library/common_test_utility_lib.h"
#include "stdio.h"

/**
 *
 +-------------------+
 | test suite result |
 +-------------------+
 |            +-------------------+
 +----------->| test group result |
 |            +-------------------+
 |                  |            +-------------------+
 |                  +----------->| test case result  |
 |                  |            +-------------------+
 |                  |
 |                  |            +-------------------+
 |                  +----------->| test case result  |
 |                               +-------------------+
 |            +-------------------+
 +----------->| test group result |
 +-------------------+
 |
 **/

typedef struct {
    uint32_t case_id;
    uint32_t total_pass;
    uint32_t total_fail;
} common_test_case_result_t;

typedef struct {
    uint32_t group_id;
    uint32_t total_pass;
    uint32_t total_fail;
    common_test_case_result_t   *test_case_results;
} common_test_group_result_t;

typedef struct {
    uint32_t total_pass;
    uint32_t total_fail;
    common_test_group_result_t  *test_group_results;
} common_test_suite_result_t;

#define COMMON_TEST_MAX_MESSAGE_LENGTH 0x800

#define COMMON_TEST_LOG_FILE_NAME "test.log"

FILE *m_log_file;
common_test_suite_result_t *m_test_suite_result;

char *common_test_result_to_string (common_test_result_t test_result)
{
    switch (test_result) {
    case COMMON_TEST_RESULT_NOT_TESTED:
        return "NOT_TESTED";
    case COMMON_TEST_RESULT_PASS:
        return "PASS";
    case COMMON_TEST_RESULT_FAIL:
        return "FAIL";
    default:
        assert (0);
        return "<UNKNOWN>";
    }
}

common_test_suite_result_t *common_test_allocate_test_suite_result (
    const common_test_suite_t *test_suite)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_t *test_group;
    common_test_case_t *test_case;
    uint32_t group_count;
    uint32_t case_count;
    uint32_t total_size;
    common_test_suite_result_t *test_suite_result;
    common_test_group_result_t *test_group_result;
    common_test_case_result_t *test_case_result;
    uint8_t *ptr;

    group_count = 0;
    case_count = 0;
    for (group_index = 0; ; group_index++) {
        group_count++;
        test_group = &test_suite->test_groups[group_index];
        if (test_group->group_id == COMMON_TEST_ID_END) {
            break;
        }
        for (case_index = 0; ; case_index++) {
            case_count++;
            test_case = &test_group->test_cases[case_index];
            if (test_case->case_id == COMMON_TEST_ID_END) {
                break;
            }
        }
    }

    total_size = sizeof(common_test_suite_result_t) +
                 (sizeof(common_test_group_result_t) * group_count) +
                 (sizeof(common_test_case_result_t) * case_count);
    test_suite_result = (common_test_suite_result_t *)malloc(total_size);
    if (test_suite_result == NULL) {
        return NULL;
    }
    ptr = (uint8_t *)test_suite_result;
    ptr += sizeof(common_test_suite_result_t);

    test_suite_result->test_group_results = (common_test_group_result_t *)ptr;
    test_suite_result->total_pass = 0;
    test_suite_result->total_fail = 0;
    ptr += (sizeof(common_test_group_result_t) * group_count);

    for (group_index = 0; ; group_index++) {
        test_group = &test_suite->test_groups[group_index];
        test_group_result = &test_suite_result->test_group_results[group_index];
        test_group_result->group_id = test_group->group_id;
        test_group_result->total_pass = 0;
        test_group_result->total_fail = 0;
        test_group_result->test_case_results = NULL;

        if (test_group->group_id == COMMON_TEST_ID_END) {
            break;
        }
        test_group_result->test_case_results = (common_test_case_result_t *)ptr;

        case_count = 0;
        for (case_index = 0; ; case_index++) {
            case_count++;
            test_case = &test_group->test_cases[case_index];
            test_case_result = &test_group_result->test_case_results[case_index];
            test_case_result->case_id = test_case->case_id;
            test_case_result->total_pass = 0;
            test_case_result->total_fail = 0;

            if (test_case->case_id == COMMON_TEST_ID_END) {
                break;
            }
        }
        ptr += (sizeof(common_test_case_result_t) * case_count);
    }

    return test_suite_result;
}

void common_test_free_test_suite_result (common_test_suite_result_t *test_suite_result)
{
    free (test_suite_result);
}

void common_test_print_test_suite_result (
    const common_test_suite_t *test_suite,
    common_test_suite_result_t *test_suite_result)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_t *test_group;
    common_test_case_t *test_case;
    common_test_group_result_t *test_group_result;
    common_test_case_result_t *test_case_result;

    fprintf (m_log_file, "\ntest suite (%s) - pass: %d, fail: %d\n",
             test_suite->name,
             test_suite_result->total_pass,
             test_suite_result->total_fail);

    for (group_index = 0; ; group_index++) {
        test_group = &test_suite->test_groups[group_index];
        test_group_result = &test_suite_result->test_group_results[group_index];
        if (test_group_result->group_id == COMMON_TEST_ID_END) {
            break;
        }
        fprintf (m_log_file,
                 "test group %d (%s) - pass: %d, fail: %d\n",
                 test_group_result->group_id,
                 test_group->group_name,
                 test_group_result->total_pass,
                 test_group_result->total_fail);
        for (case_index = 0; ; case_index++) {
            test_case = &test_group->test_cases[case_index];
            test_case_result = &test_group_result->test_case_results[case_index];
            if (test_case_result->case_id == COMMON_TEST_ID_END) {
                break;
            }
            fprintf (m_log_file,
                     "  test case %d.%d (%s) - pass: %d, fail: %d\n",
                     test_group_result->group_id,
                     test_case_result->case_id,
                     test_case->case_name,
                     test_case_result->total_pass,
                     test_case_result->total_fail);
        }
    }

    fprintf (m_log_file, "test result done\n");
}

void common_test_record_test_suite_result (
    common_test_group_id group_id,
    common_test_case_id case_id,
    common_test_result_t test_result,
    common_test_suite_result_t *test_suite_result)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_result_t *test_group_result;
    common_test_case_result_t *test_case_result;

    if (test_result == COMMON_TEST_RESULT_PASS) {
        test_suite_result->total_pass++;
    } else if (test_result == COMMON_TEST_RESULT_FAIL) {
        test_suite_result->total_fail++;
    }

    for (group_index = 0; ; group_index++) {
        test_group_result = &test_suite_result->test_group_results[group_index];
        if (test_group_result->group_id == COMMON_TEST_ID_END) {
            break;
        }
        if (test_group_result->group_id == group_id) {
            if (test_result == COMMON_TEST_RESULT_PASS) {
                test_group_result->total_pass++;
            } else if (test_result == COMMON_TEST_RESULT_FAIL) {
                test_group_result->total_fail++;
            }
            for (case_index = 0; ; case_index++) {
                test_case_result = &test_group_result->test_case_results[case_index];
                if (test_case_result->case_id == COMMON_TEST_ID_END) {
                    break;
                }
                if (test_case_result->case_id == case_id) {
                    if (test_result == COMMON_TEST_RESULT_PASS) {
                        test_case_result->total_pass++;
                    } else if (test_result == COMMON_TEST_RESULT_FAIL) {
                        test_case_result->total_fail++;
                    }
                    break;
                }
            }
            break;
        }
    }
}

void common_test_record_test_assertion (
    common_test_group_id group_id,
    common_test_case_id case_id,
    common_test_assertion_id assertion_id,
    common_test_result_t test_result,
    const char *message_format,
    ...)
{
    char buffer[COMMON_TEST_MAX_MESSAGE_LENGTH];
    va_list marker;

    fprintf(m_log_file,
            "    test assertion %d.%d.%d - %s",
            group_id, case_id, assertion_id,
            common_test_result_to_string (test_result)
            );

    if (message_format != NULL) {
        va_start(marker, message_format);

        vsnprintf(buffer, sizeof(buffer), message_format, marker);

        va_end(marker);

        fprintf(m_log_file, " %s", buffer);
    }
    fprintf(m_log_file, "\n");
    fflush(m_log_file);

    common_test_record_test_suite_result (group_id, case_id, test_result, m_test_suite_result);
}

void common_test_record_test_message(const char *message_format, ...)
{
    char buffer[COMMON_TEST_MAX_MESSAGE_LENGTH];
    va_list marker;

    va_start(marker, message_format);

    vsnprintf(buffer, sizeof(buffer), message_format, marker);

    va_end(marker);

    fprintf(m_log_file, "    test msg: %s", buffer);
    fflush(m_log_file);
}

common_test_action_t common_test_get_test_group_action (
    uint32_t group_id,
    const common_test_suite_config_t *test_suite_config)
{
    uint32_t group_index;
    common_test_group_config_t *test_group_config;

    if (test_suite_config == NULL) {
        return COMMON_TEST_ACTION_RUN;
    }

    if (test_suite_config->test_group_configs == NULL) {
        return COMMON_TEST_ACTION_RUN;
    }
    for (group_index = 0; ; group_index++) {
        test_group_config = &test_suite_config->test_group_configs[group_index];
        if (test_group_config->group_id == COMMON_TEST_ID_END) {
            break;
        }
        if (test_group_config->group_id == COMMON_TEST_ID_SKIP) {
            continue;
        }
        if (test_group_config->group_id == group_id) {
            return test_group_config->action;
        }
    }
    return COMMON_TEST_ACTION_SKIP;
}

common_test_action_t common_test_get_test_case_action (
    uint32_t group_id,
    uint32_t case_id,
    const common_test_suite_config_t *test_suite_config)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_config_t *test_group_config;
    common_test_case_config_t *test_case_config;

    if (test_suite_config == NULL) {
        return COMMON_TEST_ACTION_RUN;
    }

    for (group_index = 0; ; group_index++) {
        test_group_config = &test_suite_config->test_group_configs[group_index];
        if (test_group_config->group_id == COMMON_TEST_ID_END) {
            break;
        }
        if (test_group_config->group_id == COMMON_TEST_ID_SKIP) {
            continue;
        }
        if (test_group_config->group_id == group_id) {
            if (test_group_config->action == COMMON_TEST_ACTION_SKIP) {
                return COMMON_TEST_ACTION_SKIP;
            }
            if (test_group_config->test_case_configs == NULL) {
                return COMMON_TEST_ACTION_RUN;
            }
            for (case_index = 0; ; case_index++) {
                test_case_config = &test_group_config->test_case_configs[case_index];
                if (test_case_config->case_id == COMMON_TEST_ID_END) {
                    break;
                }
                if (test_case_config->case_id == COMMON_TEST_ID_SKIP) {
                    continue;
                }
                if (test_case_config->case_id == case_id) {
                    return test_case_config->action;
                }
            }
        }
    }
    return COMMON_TEST_ACTION_SKIP;
}

void common_test_run_test_suite (
    void *test_context,
    const common_test_suite_t *test_suite,
    const common_test_suite_config_t *test_suite_config)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_t *test_group;
    common_test_case_t *test_case;
    common_test_action_t test_action;
    bool result;

    m_log_file = fopen (COMMON_TEST_LOG_FILE_NAME, "w+");
    if (m_log_file == NULL) {
        printf("fail to create log file: %s", COMMON_TEST_LOG_FILE_NAME);
        return;
    }

    m_test_suite_result = common_test_allocate_test_suite_result (test_suite);

    if (test_suite_config != NULL && test_suite_config->config_name != NULL) {
        fprintf(m_log_file, "test_suite_config (%s)\n", test_suite_config->config_name);
    }

    assert (test_suite != NULL);
    assert (test_suite->test_groups != NULL);
    fprintf(m_log_file, "test_suite (%s)\n", test_suite->name);
    for (group_index = 0; ; group_index++) {
        test_group = &test_suite->test_groups[group_index];
        if (test_group->group_id == COMMON_TEST_ID_END) {
            break;
        }
        if (test_group->group_id == COMMON_TEST_ID_SKIP) {
            continue;
        }
        test_action = common_test_get_test_group_action (test_group->group_id, test_suite_config);
        if (test_action == COMMON_TEST_ACTION_SKIP) {
            fprintf(m_log_file, "test group %d (%s) - skipped\n", test_group->group_id,
                    test_group->group_name);
            continue;
        }
        assert (test_group->test_cases != NULL);
        fprintf(m_log_file, "test group %d (%s) - start\n", test_group->group_id,
                test_group->group_name);
        if (test_group->group_setup_func != NULL) {
            fprintf(m_log_file, "test group %d (%s) - setup enter\n", test_group->group_id,
                    test_group->group_name);
            result = test_group->group_setup_func (test_context);
            fprintf(m_log_file, "test group %d (%s) - setup exiit (%d)\n", test_group->group_id,
                    test_group->group_name, result);
            if (!result) {
                common_test_record_test_assertion (test_group->group_id, COMMON_TEST_ID_END,
                                                   COMMON_TEST_ID_END,
                                                   COMMON_TEST_RESULT_NOT_TESTED,
                                                   "group_setup_func fail");
                continue;
            }
        }
        for (case_index = 0; ; case_index++) {
            test_case = &test_group->test_cases[case_index];
            if (test_case->case_id == COMMON_TEST_ID_END) {
                break;
            }
            if (test_case->case_id == COMMON_TEST_ID_SKIP) {
                continue;
            }
            test_action = common_test_get_test_case_action (test_group->group_id,
                                                            test_case->case_id, test_suite_config);
            if (test_action == COMMON_TEST_ACTION_SKIP) {
                fprintf(m_log_file, "  test case %d.%d (%s) - skipped\n",
                        test_group->group_id,
                        test_case->case_id,
                        test_case->case_name);
                continue;
            }
            if (test_case->case_setup_func != NULL) {
                fprintf(m_log_file, "  test case %d.%d (%s) - setup enter\n",
                        test_group->group_id,
                        test_case->case_id,
                        test_case->case_name);
                result = test_case->case_setup_func (test_context);
                fprintf(m_log_file, "  test case %d.%d (%s) - setup exit (%d)\n",
                        test_group->group_id,
                        test_case->case_id,
                        test_case->case_name,
                        result);
                if (!result) {
                    common_test_record_test_assertion (test_group->group_id, test_case->case_id,
                                                       COMMON_TEST_ID_END,
                                                       COMMON_TEST_RESULT_NOT_TESTED,
                                                       "case_setup_func fail");
                    continue;
                }
            }
            fprintf(m_log_file, "  test case %d.%d (%s) - start\n",
                    test_group->group_id,
                    test_case->case_id,
                    test_case->case_name);
            test_case->case_func (test_context);
            fprintf(m_log_file, "  test case %d.%d (%s) - stop\n",
                    test_group->group_id,
                    test_case->case_id,
                    test_case->case_name);
            if (test_case->case_teardown_func != NULL) {
                fprintf(m_log_file, "  test case %d.%d (%s) - teardown enter\n",
                        test_group->group_id,
                        test_case->case_id,
                        test_case->case_name);
                test_case->case_teardown_func (test_context);
                fprintf(m_log_file, "  test case %d.%d (%s) - teardown exit\n",
                        test_group->group_id,
                        test_case->case_id,
                        test_case->case_name);
            }
        }
        if (test_group->group_teardown_func != NULL) {
            fprintf(m_log_file, "test group %d (%s) - teardown enter\n", test_group->group_id,
                    test_group->group_name);
            test_group->group_teardown_func (test_context);
            fprintf(m_log_file, "test group %d (%s) - teardown exit\n", test_group->group_id,
                    test_group->group_name);
        }
        fprintf(m_log_file, "test group %d (%s) - stop\n", test_group->group_id,
                test_group->group_name);
    }

    common_test_print_test_suite_result (test_suite, m_test_suite_result);

    common_test_free_test_suite_result (m_test_suite_result);
    m_test_suite_result = NULL;
    fclose (m_log_file);
    m_log_file = NULL;
}
