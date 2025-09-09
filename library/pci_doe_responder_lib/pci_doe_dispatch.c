/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_doe_responder_lib.h"

pci_doe_data_object_protocol_t m_data_object_protocol[] = {
    {PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY},
    {PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_SPDM},
    {PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM},
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
    uint8_t index = 0;
    uint32_t *reply = response;
    libspdm_return_t ret;

    ret = libspdm_pci_doe_decode_discovery_request(request_size, request, &index);

    if (ret != LIBSPDM_STATUS_SUCCESS) {
        return ret;
    }

    if (index >= LIBSPDM_ARRAY_SIZE(m_data_object_protocol)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    } else if (index == LIBSPDM_ARRAY_SIZE(m_data_object_protocol) - 1) {
        reply[2] = m_data_object_protocol[index].data_object_type << 16 |
                   m_data_object_protocol[index].vendor_id;
    } else {
        reply[2] = (index + 1) << 24 |
                   m_data_object_protocol[index].data_object_type << 16 |
                   m_data_object_protocol[index].vendor_id;
    }

    return libspdm_pci_doe_encode_discovery(
            sizeof(uint32_t),
            &reply[2],
            response_size,
            &response
        );
}
