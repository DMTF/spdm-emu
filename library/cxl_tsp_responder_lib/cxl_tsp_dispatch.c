/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

typedef struct {
    uint8_t op_code;
    cxl_tsp_get_response_func_t func;
} cxl_tsp_dispatch_struct_t;

cxl_tsp_dispatch_struct_t m_cxl_tsp_dispatch[] = {
    {CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION, cxl_tsp_get_response_get_version},
    {CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES, cxl_tsp_get_response_get_capabilities},
    {CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION, cxl_tsp_get_response_set_configuration},
    {CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION, cxl_tsp_get_response_get_configuration},
    {CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT, cxl_tsp_get_response_get_configuration_report},
    {CXL_TSP_OPCODE_LOCK_TARGET_CONFIGURATION, cxl_tsp_get_response_lock_configuration},
};

/**
 *  Process the TSP request and return the response.
 *
 *  @param request       the TSP request message, start from cxl_tsp_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the TSP response message, start from cxl_tsp_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_tsp_get_response (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    const cxl_tsp_header_t *tsp_request;
    size_t index;

    tsp_request = request;
    if (request_size < sizeof(cxl_tsp_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_cxl_tsp_dispatch); index++) {
        if (tsp_request->op_code == m_cxl_tsp_dispatch[index].op_code) {
            return m_cxl_tsp_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                request, request_size, response, response_size);
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
