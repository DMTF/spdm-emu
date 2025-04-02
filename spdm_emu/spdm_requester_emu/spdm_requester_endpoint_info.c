/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP

extern void *m_spdm_context;

/**
 * This function executes SPDM endpoint info.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_get_endpoint_info_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_context = m_spdm_context;

    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    status = libspdm_get_endpoint_info(spdm_context, session_id, request_attributes,
                                       sub_code, m_use_slot_id & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK,
                                       &ep_info_length, ep_info_record,
                                       NULL, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP*/