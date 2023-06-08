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
libspdm_return_t pci_tdisp_get_response_interface_state (const void *pci_doe_context,
                                                         const void *spdm_context,
                                                         const uint32_t *session_id,
                                                         const void *request, size_t request_size,
                                                         void *response, size_t *response_size)
{
    const pci_tdisp_get_device_interface_state_request_t *tdisp_request;
    pci_tdisp_device_interface_state_response_t *tdisp_response;
    libtdisp_error_code_t error_code;

    tdisp_request = request;
    tdisp_response = response;
    if (request_size != sizeof(pci_tdisp_get_device_interface_state_request_t)) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, PCI_TDISP_ERROR_CODE_INVALID_REQUEST, 0,
                                             response, response_size);
    }
    if (tdisp_request->header.version != PCI_TDISP_MESSAGE_VERSION_10) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, PCI_TDISP_ERROR_CODE_VERSION_MISMATCH, 0,
                                             response, response_size);
    }

    LIBSPDM_ASSERT (*response_size >= sizeof(pci_tdisp_device_interface_state_response_t));
    libspdm_zero_mem (response, *response_size);

    error_code = pci_tdisp_device_get_interface_state (pci_doe_context, spdm_context, session_id,
                                                       &tdisp_request->header.interface_id,
                                                       &tdisp_response->tdi_state);
    if (error_code != PCI_TDISP_ERROR_CODE_SUCCESS) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, error_code, 0,
                                             response, response_size);
    }

    *response_size = sizeof(pci_tdisp_device_interface_state_response_t);

    tdisp_response->header.version = tdisp_request->header.version;
    tdisp_response->header.message_type = PCI_TDISP_DEVICE_INTERFACE_STATE;
    tdisp_response->header.interface_id.function_id =
        tdisp_request->header.interface_id.function_id;

    return LIBSPDM_STATUS_SUCCESS;
}
