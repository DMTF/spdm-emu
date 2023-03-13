/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_ide_km_device_lib.h"

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_device_key_set_go (const void *pci_doe_context,
                                               const void *spdm_context, const uint32_t *session_id,
                                               uint8_t stream_id, uint8_t key_sub_stream,
                                               uint8_t port_index)
{
    libcxlidekm_device_port_context *device_port_context;
    uint8_t index;

    device_port_context = libcxlidekm_get_device_port_context (port_index);
    if (device_port_context == NULL) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    index = (key_sub_stream & CXL_IDE_KM_KEY_DIRECTION_MASK) >> 1;

    /* key set go */

    device_port_context->is_key_set_go[index] = true;

    return LIBSPDM_STATUS_SUCCESS;
}
