/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

void *m_mctp_context;

libspdm_return_t mctp_process_session_message(void *spdm_context, uint32_t session_id)
{
    uint8_t tid;
    libspdm_return_t status;

    status = pldm_control_get_tid (m_mctp_context, spdm_context, &session_id, &tid);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
