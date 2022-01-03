/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

void *m_mctp_context;

return_status mctp_process_session_message(IN void *spdm_context, IN uint32_t session_id)
{
    uint8_t tid;
    return_status  status;

    status = pldm_control_get_tid (m_mctp_context, spdm_context, &session_id, &tid);
    if (RETURN_ERROR(status)) {
        return status;
    }

    return RETURN_SUCCESS;
}
