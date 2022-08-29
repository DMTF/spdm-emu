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

typedef struct {
    uint8_t object_id;
    cxl_ide_km_get_response_func_t func;
} cxl_ide_km_dispatch_struct_t;

cxl_ide_km_dispatch_struct_t m_cxl_ide_km_dispatch[] = {
    {CXL_IDE_KM_OBJECT_ID_QUERY, cxl_ide_km_get_response_query},
    {CXL_IDE_KM_OBJECT_ID_KEY_PROG, cxl_ide_km_get_response_key_prog},
    {CXL_IDE_KM_OBJECT_ID_K_SET_GO, cxl_ide_km_get_response_key_set_go},
    {CXL_IDE_KM_OBJECT_ID_K_SET_STOP, cxl_ide_km_get_response_key_set_stop},
    {CXL_IDE_KM_OBJECT_ID_GET_KEY, cxl_ide_km_get_response_get_key},
};

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
libspdm_return_t cxl_ide_km_get_response (const void *pci_doe_context,
                                          const void *spdm_context, const uint32_t *session_id,
                                          const void *request, size_t request_size,
                                          void *response, size_t *response_size)
{
    const cxl_ide_km_header_t *ide_km_request;
    size_t index;

    ide_km_request = request;
    if (request_size < sizeof(cxl_ide_km_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_cxl_ide_km_dispatch); index++) {
        if (ide_km_request->object_id == m_cxl_ide_km_dispatch[index].object_id) {
            return m_cxl_ide_km_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                request, request_size, response, response_size);
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
