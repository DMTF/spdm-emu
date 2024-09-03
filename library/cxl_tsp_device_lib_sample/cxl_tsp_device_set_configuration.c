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
libcxltsp_error_code_t cxl_tsp_device_set_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const libcxltsp_device_configuration_t *device_configuration,
    const libcxltsp_device_2nd_session_info_t *device_2nd_session_info)
{
    libcxltsp_device_context *device_context;

    device_context = libcxltsp_get_device_context (pci_doe_context);
    if (device_context == NULL) {
        return CXL_TSP_ERROR_CODE_UNSPECIFIED;
    }
    libspdm_copy_mem (&device_context->device_configuration,
                      sizeof(libcxltsp_device_configuration_t),
                      device_configuration,
                      sizeof(libcxltsp_device_configuration_t));
    libspdm_copy_mem (&device_context->device_2nd_session_info,
                      sizeof(libcxltsp_device_2nd_session_info_t),
                      device_2nd_session_info,
                      sizeof(libcxltsp_device_2nd_session_info_t));

    return CXL_TSP_ERROR_CODE_SUCCESS;
}
