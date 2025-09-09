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
#include "library/pci_tdisp_responder_lib.h"
#include "library/pci_tdisp_device_lib.h"

#pragma pack(1)
typedef struct {
    pci_tdisp_header_t header;
    uint8_t version_num_count;
    pci_tdisp_version_number_t version_num_entry[LIBTDISP_MAX_VERSION_COUNT];
} pci_tdisp_version_response_mine_t;
#pragma pack()

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
libspdm_return_t pci_tdisp_get_response_version (const void *pci_doe_context,
                                                 const void *spdm_context,
                                                 const uint32_t *session_id,
                                                 const void *request, size_t request_size,
                                                 void *response, size_t *response_size)
{
    const pci_tdisp_get_version_request_t *tdisp_request;
    pci_tdisp_version_response_mine_t *tdisp_response;
    libtdisp_error_code_t error_code;

    tdisp_request = request;
    tdisp_response = response;
    if (request_size != sizeof(pci_tdisp_get_version_request_t)) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, PCI_TDISP_ERROR_CODE_INVALID_REQUEST, 0,
                                             response, response_size);
    }
    if (tdisp_request->header.version != PCI_TDISP_MESSAGE_VERSION_10) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, PCI_TDISP_ERROR_CODE_VERSION_MISMATCH, 0,
                                             response, response_size);
    }

    LIBSPDM_ASSERT (*response_size >= sizeof(pci_tdisp_version_response_mine_t));
    libspdm_zero_mem (response, *response_size);
    tdisp_response->version_num_count = LIBTDISP_MAX_VERSION_COUNT;

    error_code = pci_tdisp_device_get_version (pci_doe_context, spdm_context, session_id,
                                               &tdisp_request->header.interface_id,
                                               &tdisp_response->version_num_count,
                                               tdisp_response->version_num_entry);
    if (error_code != PCI_TDISP_ERROR_CODE_SUCCESS) {
        return pci_tdisp_get_response_error (pci_doe_context, spdm_context, session_id,
                                             request, error_code, 0,
                                             response, response_size);
    }

    *response_size = sizeof(pci_tdisp_version_response_mine_t);

    tdisp_response->header.version = tdisp_request->header.version;
    tdisp_response->header.message_type = PCI_TDISP_VERSION;
    tdisp_response->header.interface_id.function_id =
        tdisp_request->header.interface_id.function_id;

    return LIBSPDM_STATUS_SUCCESS;
}
