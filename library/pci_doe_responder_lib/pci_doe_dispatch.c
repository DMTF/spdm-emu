/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_responder_lib.h"

typedef struct {
    pci_doe_data_object_protocol_t protocol;
    pci_doe_get_response_func_t func;
} pci_doe_dispatch_struct_t;

pci_doe_dispatch_struct_t m_pci_doe_dispatch[] = {
    {{PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY},
     pci_doe_get_response_discovery},
};

/**
 *  Process the DOE request and return the response.
 *
 *  @param request       the PCI_DOE request message, start from pci_doe_data_object_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the PCI_DOE response message, start from pci_doe_data_object_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pci_doe_get_response_doe_request(const void *pci_doe_context,
                                               const void *request, size_t request_size,
                                               void *response, size_t *response_size)
{
    pci_doe_data_object_header_t *doe_request;
    size_t index;

    doe_request = (void *)request;
    if (request_size < sizeof(doe_request)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    for (index = 0; index < ARRAY_SIZE(m_pci_doe_dispatch); index++) {
        if ((doe_request->vendor_id == m_pci_doe_dispatch[index].protocol.vendor_id) &&
            (doe_request->data_object_type ==
             m_pci_doe_dispatch[index].protocol.data_object_type)) {
            return m_pci_doe_dispatch[index].func (pci_doe_context, request, request_size, response,
                                                   response_size);
        }
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
