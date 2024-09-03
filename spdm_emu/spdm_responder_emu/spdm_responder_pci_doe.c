/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

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
    status = pci_doe_register_vendor_response_func (
        m_pci_doe_context,
        SPDM_REGISTRY_ID_PCISIG, SPDM_VENDOR_ID_CXL,
        CXL_PROTOCOL_ID_IDE_KM, cxl_ide_km_get_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    status = pci_doe_register_vendor_response_func (
        m_pci_doe_context,
        SPDM_REGISTRY_ID_PCISIG, SPDM_VENDOR_ID_CXL,
        CXL_PROTOCOL_ID_TSP, cxl_tsp_get_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}
