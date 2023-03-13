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
#include "library/spdm_crypt_lib.h"

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
libspdm_return_t cxl_ide_km_device_get_key (const void *pci_doe_context,
                                            const void *spdm_context, const uint32_t *session_id,
                                            uint8_t stream_id, uint8_t key_sub_stream,
                                            uint8_t port_index,
                                            cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer)
{
    libcxlidekm_device_port_context *device_port_context;
    bool result;

    device_port_context = libcxlidekm_get_device_port_context (port_index);
    if (device_port_context == NULL) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    /* get key */

    result = libspdm_get_random_number(sizeof(key_buffer->key), (void *)key_buffer->key);
    if (!result) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    key_buffer->iv[0] = 0;
    key_buffer->iv[1] = 1;
    key_buffer->iv[2] = 2;

    return LIBSPDM_STATUS_SUCCESS;
}
