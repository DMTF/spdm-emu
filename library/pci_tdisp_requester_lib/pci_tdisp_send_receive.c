/**
 *  Copyright Notice:
 *  Copyright 2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_requester_lib.h"

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the TDISP request message, start from pci_tdisp_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the TDISP response message, start from pci_tdisp_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_send_receive_data (void *spdm_context, const uint32_t *session_id,
                                              const void *request, size_t request_size,
                                              void *response, size_t *response_size)
{
    libspdm_return_t status;
    pci_protocol_header_t pci_protocol;

    pci_protocol.protocol_id = PCI_PROTOCOL_ID_TDISP;
    status = pci_doe_spdm_vendor_send_receive_data (spdm_context, session_id,
                                                    pci_protocol,
                                                    request, request_size, response, response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
