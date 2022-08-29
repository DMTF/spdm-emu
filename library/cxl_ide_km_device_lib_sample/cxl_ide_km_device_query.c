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
libspdm_return_t cxl_ide_km_device_query (const void *pci_doe_context,
                                          const void *spdm_context, const uint32_t *session_id,
                                          uint8_t port_index, uint8_t *dev_func_num,
                                          uint8_t *bus_num, uint8_t *segment, uint8_t *max_port_index,
                                          uint8_t *caps,
                                          uint32_t **ide_reg_buffer, uint32_t *ide_reg_buffer_count)
{
    libcxlidekm_device_port_context *device_port_context;

    device_port_context = libcxlidekm_initialize_device_port_context (port_index);
    if (device_port_context == NULL) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    *dev_func_num = device_port_context->dev_func_num;
    *bus_num = device_port_context->bus_num;
    *segment = device_port_context->segment;
    *max_port_index = device_port_context->max_port_index;
    *caps = device_port_context->caps;
    *ide_reg_buffer = device_port_context->ide_reg_buffer;
    *ide_reg_buffer_count = device_port_context->ide_reg_buffer_count;

    return LIBSPDM_STATUS_SUCCESS;
}
