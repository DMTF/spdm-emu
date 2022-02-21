/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_requester_lib.h"

/**
  Send and receive an IDE_KM message

  @param  spdm_context                 A pointer to the SPDM context.
  @param  session_id                   Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param request                       the IDE_KM request message, start from pci_ide_km_header_t.
  @param request_size                  size in bytes of request.
  @param response                      the IDE_KM response message, start from pci_ide_km_header_t.
  @param response_size                 size in bytes of response.

  @retval RETURN_SUCCESS               The IDM_KM request is sent and response is received.
  @return ERROR                        The IDM_KM response is not received correctly.
**/
return_status ide_km_send_receive_data (void *spdm_context, const uint32_t *session_id,
                    const void *request, uintn request_size,
                    void *response, uintn *response_size)
{
    return_status status;
    pci_protocol_header_t pci_protocol;

    pci_protocol.protocol_id = PCI_PROTOCOL_ID_IDE_KM;
    status = pci_doe_spdm_vendor_send_receive_data (spdm_context, session_id,
                    pci_protocol,
                    request, request_size, response, response_size);
    if (RETURN_ERROR(status)) {
        return status;
    }

    return RETURN_SUCCESS;
}
