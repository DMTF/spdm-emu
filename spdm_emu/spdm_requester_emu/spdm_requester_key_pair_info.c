/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

extern void *m_spdm_context;

/**
 * This function executes SPDM get_key_pair_info.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_get_key_pair_info_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;

    uint8_t key_pair_id;
    uint8_t total_key_pairs;
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];

    spdm_context = m_spdm_context;

    key_pair_id = 1;
    public_key_info_len = SPDM_MAX_PUBLIC_KEY_INFO_LEN;

    status = libspdm_get_key_pair_info(spdm_context, session_id,
                                       key_pair_id, &total_key_pairs,
                                       &capabilities,
                                       &key_usage_capabilities,
                                       &current_key_usage,
                                       &asym_algo_capabilities,
                                       &current_asym_algo,
                                       &assoc_cert_slot_mask,
                                       &public_key_info_len,
                                       public_key_info);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/
