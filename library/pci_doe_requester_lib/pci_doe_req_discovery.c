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

/* Vendor message*/

#pragma pack(1)

/* DOE Discovery request*/

typedef struct {
    pci_doe_data_object_header_t doe_header;
    pci_doe_discovery_request_t doe_discovery_request;
} doe_discovery_request_mine_t;


/* DOE Discovery response*/

typedef struct {
    pci_doe_data_object_header_t doe_header;
    pci_doe_discovery_response_t doe_discovery_response;
} doe_discovery_response_mine_t;

#pragma pack()

return_status pci_doe_discovery (const void *pci_doe_context,
    pci_doe_data_object_protocol_t *data_object_protocol,
    uintn *data_object_protocol_size)
{
    doe_discovery_request_mine_t doe_request;
    doe_discovery_response_mine_t doe_response;
    uintn response_size;
    return_status status;
    uintn total_index;
    uintn current_index;

    current_index = 0;
    total_index = *data_object_protocol_size /
                        sizeof(pci_doe_data_object_protocol_t);

    zero_mem(&doe_request, sizeof(doe_request));
    doe_request.doe_header.vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    doe_request.doe_header.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
    doe_request.doe_header.length = sizeof(doe_discovery_request_mine_t) / sizeof(uint32_t);
    doe_request.doe_discovery_request.index = 0;

    do {
        if (total_index < 
                (uintn)doe_request.doe_discovery_request.index + 1) {
            return RETURN_BUFFER_TOO_SMALL;
        }

        response_size = sizeof(doe_response);
        status = pci_doe_send_receive_data (
                    pci_doe_context,
                    sizeof(doe_request), (uint8_t *)&doe_request,
                    &response_size, (uint8_t *)&doe_response);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }
        if (response_size != sizeof(doe_response)) {
            return RETURN_DEVICE_ERROR;
        }
        if (doe_response.doe_header.vendor_id !=
            PCI_DOE_VENDOR_ID_PCISIG) {
            return RETURN_DEVICE_ERROR;
        }
        if (doe_response.doe_header.data_object_type !=
            PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY) {
            return RETURN_DEVICE_ERROR;
        }
        if (doe_response.doe_header.length !=
            sizeof(doe_response) / sizeof(uint32_t)) {
            return RETURN_DEVICE_ERROR;
        }

        if ((doe_response.doe_discovery_response.next_index != 0) &&
            (doe_response.doe_discovery_response.next_index !=
             doe_request.doe_discovery_request.index + 1)) {
            return RETURN_DEVICE_ERROR;
        }

        current_index = doe_request.doe_discovery_request.index;
        data_object_protocol[current_index].vendor_id =
            doe_response.doe_discovery_response.vendor_id;
        data_object_protocol[current_index].data_object_type =
            doe_response.doe_discovery_response.data_object_type;

        doe_request.doe_discovery_request.index =
                doe_response.doe_discovery_response.next_index;
    } while (doe_response.doe_discovery_response.next_index != 0);

    ASSERT ((current_index + 1) <= total_index);

    *data_object_protocol_size = (current_index + 1) *
                        sizeof(pci_doe_data_object_protocol_t);

    return RETURN_SUCCESS;
}
