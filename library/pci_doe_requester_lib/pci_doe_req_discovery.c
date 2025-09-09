/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
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

libspdm_return_t pci_doe_discovery (const void *pci_doe_context,
                                    pci_doe_data_object_protocol_t *data_object_protocol,
                                    size_t *data_object_protocol_size,
                                    uint8_t version)
{
    doe_discovery_request_mine_t doe_request;
    doe_discovery_response_mine_t doe_response;
    size_t response_size;
    libspdm_return_t status;
    size_t total_index;
    size_t current_index;

    current_index = 0;
    total_index = *data_object_protocol_size /
                  sizeof(pci_doe_data_object_protocol_t);

    libspdm_zero_mem(&doe_request, sizeof(doe_request));
    doe_request.doe_header.vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    doe_request.doe_header.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
    doe_request.doe_header.length = sizeof(doe_discovery_request_mine_t) / sizeof(uint32_t);
    doe_request.doe_discovery_request.index = 0;
    doe_request.doe_discovery_request.version = version;

    do {
        if (total_index <
            (size_t)doe_request.doe_discovery_request.index + 1) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }

        response_size = sizeof(doe_response);
        status = pci_doe_send_receive_data (
            pci_doe_context,
            sizeof(doe_request), (uint8_t *)&doe_request,
            &response_size, (uint8_t *)&doe_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        if (response_size != sizeof(doe_response)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (doe_response.doe_header.vendor_id !=
            PCI_DOE_VENDOR_ID_PCISIG) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (doe_response.doe_header.data_object_type !=
            PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (doe_response.doe_header.length !=
            sizeof(doe_response) / sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if ((doe_response.doe_discovery_response.next_index != 0) &&
            (doe_response.doe_discovery_response.next_index !=
             doe_request.doe_discovery_request.index + 1)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        current_index = doe_request.doe_discovery_request.index;
        data_object_protocol[current_index].vendor_id =
            doe_response.doe_discovery_response.vendor_id;
        data_object_protocol[current_index].data_object_type =
            doe_response.doe_discovery_response.data_object_type;

        doe_request.doe_discovery_request.index =
            doe_response.doe_discovery_response.next_index;
    } while (doe_response.doe_discovery_response.next_index != 0);

    LIBSPDM_ASSERT ((current_index + 1) <= total_index);

    *data_object_protocol_size = (current_index + 1) *
                                 sizeof(pci_doe_data_object_protocol_t);

    return LIBSPDM_STATUS_SUCCESS;
}
