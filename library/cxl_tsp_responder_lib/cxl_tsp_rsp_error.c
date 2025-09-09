/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_responder_lib.h"
#include "library/cxl_tsp_device_lib.h"

/**
 *  Process the TSP request and return the response.
 *
 *  @param request       the TSP request message, start from pci_tsp_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the TSP response message, start from pci_tsp_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_tsp_get_response_error (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const cxl_tsp_header_t *tsp_header,
    uint32_t error_code, uint32_t error_data,
    void *response, size_t *response_size)
{
    cxl_tsp_error_rsp_t *tsp_response;

    tsp_response = response;

    LIBSPDM_ASSERT (*response_size >= sizeof(cxl_tsp_error_rsp_t));
    *response_size = sizeof(cxl_tsp_error_rsp_t);

    libspdm_zero_mem (response, *response_size);
    tsp_response->header.tsp_version = tsp_header->tsp_version;
    tsp_response->header.op_code = CXL_TSP_OPCODE_ERROR_RSP;

    tsp_response->error_code = error_code;
    tsp_response->error_data = error_data;

    return LIBSPDM_STATUS_SUCCESS;
}
