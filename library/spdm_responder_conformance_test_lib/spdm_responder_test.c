/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

common_test_group_t m_spdm_test_groups[] = {
    {SPDM_RESPONDER_TEST_GROUP_VERSION,           "spdm_test_group_version",
     m_spdm_test_group_version},
    {SPDM_RESPONDER_TEST_GROUP_CAPABILITIES,      "spdm_test_group_capabilities",
     m_spdm_test_group_capabilities},
    {SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,        "spdm_test_group_algorithms",
     m_spdm_test_group_algorithms},
    {SPDM_RESPONDER_TEST_GROUP_DIGESTS,           "spdm_test_group_digests",
     m_spdm_test_group_digests},
    {SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,       "spdm_test_group_certificate",
     m_spdm_test_group_certificate},
    {SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,    "spdm_test_group_challenge_auth",
     m_spdm_test_group_challenge_auth},
    {SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS,      "spdm_test_group_measurements",
     m_spdm_test_group_measurements},
    {SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,  "spdm_test_group_key_exchange_rsp",
     m_spdm_test_group_key_exchange_rsp},
    {SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,        "spdm_test_group_finish_rsp",
     m_spdm_test_group_finish_rsp},
    {SPDM_RESPONDER_TEST_GROUP_HEARTBEAT_ACK,     "spdm_test_group_heartbeat_ack",
     m_spdm_test_group_heartbeat_ack},
    {SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,    "spdm_test_group_key_update_ack",
     m_spdm_test_group_key_update_ack},
    {SPDM_RESPONDER_TEST_GROUP_END_SESSION_ACK,   "spdm_test_group_end_session_ack",
     m_spdm_test_group_end_session_ack},
    {COMMON_TEST_ID_END, NULL, NULL},
};

common_test_suite_t m_spdm_test_suite = {
    "spdm_responder_conformance_test",
    m_spdm_test_groups,
};

void spdm_responder_conformance_test (void *spdm_context,
                                      const common_test_suite_config_t *test_config)
{
    spdm_test_context_t spdm_test_context;

    libspdm_zero_mem(&spdm_test_context, sizeof(spdm_test_context_t));
    spdm_test_context.spdm_context = spdm_context;
    common_test_run_test_suite (&spdm_test_context, &m_spdm_test_suite, test_config);
}
