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

extern uint8_t m_cxl_tsp_2nd_session_psk[CXL_TSP_2ND_SESSION_COUNT][CXL_TSP_2ND_SESSION_KEY_SIZE];

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
    size_t index;

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

    for (index = 0; index < CXL_TSP_2ND_SESSION_COUNT; index++) {
        if ((device_context->device_2nd_session_info.configuration_validity_flags & (0x1 << index)) != 0) {
            libspdm_copy_mem(
                m_cxl_tsp_2nd_session_psk[index],
                sizeof(m_cxl_tsp_2nd_session_psk[index]),
                &device_context->device_2nd_session_info.secondary_session_psk_key_material[index],
                sizeof(device_context->device_2nd_session_info.secondary_session_psk_key_material[index]));
        }
    }
    return CXL_TSP_ERROR_CODE_SUCCESS;
}
