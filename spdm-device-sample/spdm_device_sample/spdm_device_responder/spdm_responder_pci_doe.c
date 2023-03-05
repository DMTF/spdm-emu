/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"
#include "library/pci_doe_responder_lib.h"
#include "library/pci_ide_km_responder_lib.h"
#include "library/pci_tdisp_responder_lib.h"

void *m_pci_doe_context;

libspdm_return_t pci_doe_init_responder()
{
    libspdm_return_t status;
    status = pci_doe_register_vendor_response_func (
                m_pci_doe_context,
                SPDM_REGISTRY_ID_PCISIG, SPDM_VENDOR_ID_PCISIG,
                PCI_PROTOCOL_ID_IDE_KM, pci_ide_km_get_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    status = pci_doe_register_vendor_response_func (
                m_pci_doe_context,
                SPDM_REGISTRY_ID_PCISIG, SPDM_VENDOR_ID_PCISIG,
                PCI_PROTOCOL_ID_TDISP, pci_tdisp_get_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_get_response_vendor_defined_request(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    libspdm_return_t status;

    LIBSPDM_ASSERT(!is_app_message);
    status = pci_doe_get_response_spdm_vendor_defined_request (
             m_pci_doe_context, spdm_context, session_id,
             request, request_size, response, response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_generate_error_response(spdm_context,
                                        SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                        response_size, response);
    }
    return LIBSPDM_STATUS_SUCCESS;
}
