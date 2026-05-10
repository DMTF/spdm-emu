/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/library/responder/keyexlib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
bool libspdm_key_exchange_rsp_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_hash_type,
    uint8_t slot_id,
    uint8_t session_policy,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_finish_rsp_opaque_data(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t req_slot_id,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    *opaque_data_size = 0;
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
