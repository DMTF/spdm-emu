/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_responder_lib.h"
#include "library/pci_tdisp_device_lib.h"

typedef struct {
    uint8_t message_type;
    pci_tdisp_get_response_func_t func;
} pci_tdisp_dispatch_struct_t;

pci_tdisp_dispatch_struct_t m_pci_tdisp_dispatch[] = {
    {PCI_TDISP_GET_VERSION, pci_tdisp_get_response_version},
    {PCI_TDISP_GET_CAPABILITIES, pci_tdisp_get_response_capabilities},
    {PCI_TDISP_LOCK_INTERFACE_REQ, pci_tdisp_get_response_lock_interface},
    {PCI_TDISP_GET_DEVICE_INTERFACE_REPORT, pci_tdisp_get_response_interface_report},
    {PCI_TDISP_GET_DEVICE_INTERFACE_STATE, pci_tdisp_get_response_interface_state},
    {PCI_TDISP_START_INTERFACE_REQ, pci_tdisp_get_response_start_interface},
    {PCI_TDISP_STOP_INTERFACE_REQ, pci_tdisp_get_response_stop_interface},
};

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
libspdm_return_t pci_tdisp_get_response (const void *pci_doe_context,
                                         const void *spdm_context, const uint32_t *session_id,
                                         const void *request, size_t request_size,
                                         void *response, size_t *response_size)
{
    const pci_tdisp_header_t *tdisp_request;
    size_t index;

    tdisp_request = request;
    if (request_size < sizeof(pci_tdisp_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pci_tdisp_dispatch); index++) {
        if (tdisp_request->message_type == m_pci_tdisp_dispatch[index].message_type) {
            return m_pci_tdisp_dispatch[index].func (
                pci_doe_context, spdm_context, session_id,
                request, request_size, response, response_size);
        }
    }

    return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                         request, PCI_TDISP_ERROR_CODE_UNSUPPORTED_REQUEST,
                                         tdisp_request->message_type,
                                         response, response_size);
}
