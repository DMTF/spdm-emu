/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef _SPDM_RESPONDER_TEST_H_
#define _SPDM_RESPONDER_TEST_H_

#include "library/spdm_requester_lib.h"
#include "internal/libspdm_requester_lib.h"

#include "library/spdm_responder_conformance_test_lib.h"
#include "library/common_test_utility_lib.h"

#define SPDM_TEST_VERSION_MASK_V10 0x00000001
#define SPDM_TEST_VERSION_MASK_V11 0x00000002
#define SPDM_TEST_VERSION_MASK_V12 0x00000004

#define SPDM_TEST_SCRATCH_BUFFER_SIZE 0x1000

typedef struct {
    void *spdm_context;
    /* test case specific scratch buffer between setup and case, avoid writable global variable */
    uint8_t test_scratch_buffer[SPDM_TEST_SCRATCH_BUFFER_SIZE];
    uint32_t test_scratch_buffer_size;
} spdm_test_context_t;

/**
 * return one bit in the data according to the mask
 *
 * @retval 0                if (data & mask) is 0.
 * @retval 0xFFFFFFFF       if (data & mask) includes more than one bit.
 * @return (data & mask)    if (data & mask) includes one bit.
 **/
uint32_t spdm_test_get_one_bit (uint32_t data, uint32_t mask);

extern common_test_case_t m_spdm_test_group_version[];
extern common_test_case_t m_spdm_test_group_capabilities[];
extern common_test_case_t m_spdm_test_group_algorithms[];
extern common_test_case_t m_spdm_test_group_digests[];
extern common_test_case_t m_spdm_test_group_certificate[];
extern common_test_case_t m_spdm_test_group_challenge_auth[];
extern common_test_case_t m_spdm_test_group_measurements[];
extern common_test_case_t m_spdm_test_group_key_exchange_rsp[];
extern common_test_case_t m_spdm_test_group_finish_rsp[];
extern common_test_case_t m_spdm_test_group_heartbeat_ack[];
extern common_test_case_t m_spdm_test_group_key_update_ack[];
extern common_test_case_t m_spdm_test_group_end_session_ack[];

#endif
