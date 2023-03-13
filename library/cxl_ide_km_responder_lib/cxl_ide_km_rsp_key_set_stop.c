/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
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
libspdm_return_t cxl_ide_km_get_response_key_set_stop (const void *pci_doe_context,
                                                       const void *spdm_context,
                                                       const uint32_t *session_id,
                                                       const void *request, size_t request_size,
                                                       void *response, size_t *response_size)
{
    const cxl_ide_km_k_set_stop_t *ide_km_request;
    cxl_ide_km_k_gostop_ack_t *ide_km_response;
    libspdm_return_t status;

    ide_km_request = request;
    ide_km_response = response;
    if (request_size != sizeof(cxl_ide_km_k_set_stop_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size >= sizeof(cxl_ide_km_k_gostop_ack_t));
    *response_size = sizeof(cxl_ide_km_k_gostop_ack_t);

    libspdm_zero_mem (response, *response_size);
    ide_km_response->header.object_id = CXL_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK;

    ide_km_response->stream_id = ide_km_request->stream_id;
    ide_km_response->key_sub_stream = ide_km_request->key_sub_stream;
    ide_km_response->port_index = ide_km_request->port_index;

    status = cxl_ide_km_device_key_set_stop (pci_doe_context, spdm_context, session_id,
                                             ide_km_request->stream_id,
                                             ide_km_request->key_sub_stream,
                                             ide_km_request->port_index
                                             );
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
