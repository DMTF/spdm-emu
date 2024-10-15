/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

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
libcxltsp_error_code_t cxl_tsp_device_get_version (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    uint8_t *version_number_entry_count,
    cxl_tsp_version_number_t *version_number_entry)
{
    libcxltsp_device_context *device_context;

    device_context = libcxltsp_initialize_device_context (pci_doe_context);
    if (device_context == NULL) {
        return CXL_TSP_ERROR_CODE_UNSPECIFIED;
    }

    libcxltsp_initialize_session_id ((void *)spdm_context, *session_id);

    libspdm_copy_mem (version_number_entry,
                      sizeof(cxl_tsp_version_number_t) * (*version_number_entry_count),
                      device_context->supported_tsp_versions,
                      sizeof(cxl_tsp_version_number_t) *
                      device_context->supported_tsp_versions_count);
    *version_number_entry_count = device_context->supported_tsp_versions_count;

    return CXL_TSP_ERROR_CODE_SUCCESS;
}
