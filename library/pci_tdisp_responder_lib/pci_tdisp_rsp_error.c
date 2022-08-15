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
#include "library/pci_tdisp_responder_lib.h"
#include "library/pci_tdisp_device_lib.h"

/**
 *  Process the TDISP request and return the response.
 *
 *  @param request       the TDISP request message, start from pci_tdisp_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the TDISP response message, start from pci_tdisp_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pci_tdisp_get_response_error (const void *pci_doe_context,
                                               const void *spdm_context, const uint32_t *session_id,
                                               const pci_tdisp_header_t *tdisp_header,
                                               uint32_t error_code, uint32_t error_data,
                                               void *response, size_t *response_size)
{
    pci_tdisp_error_response_t *tdisp_response;

    tdisp_response = response;

    LIBSPDM_ASSERT (*response_size >= sizeof(pci_tdisp_error_response_t));
    *response_size = sizeof(pci_tdisp_error_response_t);

    libspdm_zero_mem (response, *response_size);
    tdisp_response->header.version = tdisp_header->version;
    tdisp_response->header.message_type = PCI_TDISP_ERROR;
    tdisp_response->header.interface_id.function_id = tdisp_header->interface_id.function_id;

    tdisp_response->error_code = error_code;
    tdisp_response->error_data = error_data;

    return LIBSPDM_STATUS_SUCCESS;
}
