/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
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
libtdisp_error_code_t pci_tdisp_device_get_interface_report (const void *pci_doe_context,
                                                             const void *spdm_context,
                                                             const uint32_t *session_id,
                                                             const pci_tdisp_interface_id_t *interface_id,
                                                             uint8_t **interface_report, uint16_t *interface_report_size)
{
    libtdisp_interface_context *interface_context;

    interface_context = libtdisp_get_interface_context (interface_id);
    if (interface_context == NULL) {
        return PCI_TDISP_ERROR_CODE_INVALID_INTERFACE;
    }
    *interface_report_size = interface_context->interface_report_size;
    *interface_report = interface_context->interface_report;

    return PCI_TDISP_ERROR_CODE_SUCCESS;
}
