/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_EMU_NV_STORAGE_LIB_H__
#define __SPDM_EMU_NV_STORAGE_LIB_H__

#include "hal/base.h"
#include "industry_standard/spdm.h"

#define SPDM_NEGOTIATED_STATE_STRUCT_VERSION 1

#pragma pack(1)
typedef struct {
    uint32_t version;
    uint8_t spdm_version;
    uint8_t requester_cap_ct_exponent;
    uint32_t requester_cap_flags;
    uint8_t responder_cap_ct_exponent;
    uint32_t responder_cap_flags;
    uint8_t measurement_spec;
    uint8_t other_params_support;
    uint8_t mel_spec;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint16_t dhe_named_group;
    uint16_t aead_cipher_suite;
    uint16_t req_base_asym_alg;
    uint16_t key_schedule;
    size_t vca_buffer_size;
    uint8_t vca_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];
} spdm_negotiated_state_struct_t;
#pragma pack()

/**
 * privision the capability and algorithm for PKS version only case.
 */
libspdm_return_t spdm_provision_psk_version_only(void *spdm_context,
                                                 bool is_requester);

/**
 * Load the negotiated_state from NV storage to an SPDM context.
 */
libspdm_return_t spdm_load_negotiated_state(void *spdm_context,
                                            bool is_requester);

/**
 * Save the negotiated_state to NV storage from an SPDM context.
 */
libspdm_return_t spdm_save_negotiated_state(void *spdm_context,
                                            bool is_requester);

/**
 * Clear the negotiated_state in the NV storage.
 */
libspdm_return_t spdm_clear_negotiated_state(void *spdm_context);

#endif
