/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_device_lib.h"

#define MMIO_RANGE_COUNT 4
#define DEVICE_INFO_LEN  16

typedef struct {
    uint16_t interface_info;
    uint16_t reserved; 
    uint16_t msi_x_message_control;
    uint16_t lnr_control;
    uint32_t tph_control;
    uint32_t mmio_range_count;
    pci_tdisp_mmio_range_t mmio_range[MMIO_RANGE_COUNT];
    uint32_t device_specific_info_len;
    uint8_t device_specific_info[DEVICE_INFO_LEN];
} pci_tdisp_device_interface_report_struct_mine_t;

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
libtdisp_error_code_t pci_tdisp_device_lock_interface (const void *pci_doe_context,
                                                       const void *spdm_context, const uint32_t *session_id,
                                                       const pci_tdisp_interface_id_t *interface_id,
                                                       const pci_tdisp_lock_interface_param_t *lock_interface_param,
                                                       uint8_t *start_interface_nonce)
{
    libtdisp_interface_context *interface_context;
    bool result;
    pci_tdisp_device_interface_report_struct_mine_t *interface_report;

    interface_context = libtdisp_get_interface_context (interface_id);
    if (interface_context == NULL) {
        return PCI_TDISP_ERROR_CODE_INVALID_INTERFACE;
    }
    if (interface_context->tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED) {
        return PCI_TDISP_ERROR_CODE_INVALID_INTERFACE_STATE;
    }
    libspdm_copy_mem (&interface_context->lock_interface_param,
                      sizeof(interface_context->lock_interface_param),
                      lock_interface_param,
                      sizeof(*lock_interface_param));
    result = libspdm_random_bytes(start_interface_nonce, sizeof(*start_interface_nonce));
    if (!result) {
        return PCI_TDISP_ERROR_CODE_INSUFFICIENT_ENTROPY;
    }

    libspdm_copy_mem (&interface_context->start_interface_nonce,
                      sizeof(interface_context->start_interface_nonce),
                      start_interface_nonce,
                      sizeof(*start_interface_nonce));

    /* lock the interface */

    interface_context->tdi_state = PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED;

    /* generate the report */

    interface_report = (void *)interface_context->interface_report;
    interface_context->interface_report_size = sizeof(pci_tdisp_device_interface_report_struct_mine_t);
    libspdm_zero_mem (interface_report, sizeof(pci_tdisp_device_interface_report_struct_mine_t));
    interface_report->interface_info = PCI_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK |
                                       PCI_TDISP_INTERFACE_INFO_DMA_WITHOUT_PASID;
    interface_report->msi_x_message_control = 0;
    interface_report->lnr_control = 0;
    interface_report->tph_control = 0;
    interface_report->mmio_range_count = MMIO_RANGE_COUNT;
    interface_report->mmio_range[0].first_page = 0x0000;
    interface_report->mmio_range[0].number_of_pages = 1;
    interface_report->mmio_range[0].range_attributes = PCI_TDISP_MMIO_RANGE_ATTRIBUTES_IS_NON_TEE_MEM;
    interface_report->mmio_range[0].range_id = 1;

    interface_report->mmio_range[1].first_page = 0x8000;
    interface_report->mmio_range[1].number_of_pages = 4;
    interface_report->mmio_range[1].range_attributes = PCI_TDISP_MMIO_RANGE_ATTRIBUTES_IS_MEM_ATTR_UPDATABLE;
    interface_report->mmio_range[1].range_id = 2;

    interface_report->mmio_range[2].first_page = 0x10000;
    interface_report->mmio_range[2].number_of_pages = 8;
    interface_report->mmio_range[2].range_attributes = PCI_TDISP_MMIO_RANGE_ATTRIBUTES_IS_MEM_ATTR_UPDATABLE;
    interface_report->mmio_range[2].range_id = 3;

    interface_report->mmio_range[3].first_page = 0x20000;
    interface_report->mmio_range[3].number_of_pages = 8;
    interface_report->mmio_range[3].range_attributes = PCI_TDISP_MMIO_RANGE_ATTRIBUTES_IS_MEM_ATTR_UPDATABLE;
    interface_report->mmio_range[3].range_id = 4;

    interface_report->device_specific_info_len = DEVICE_INFO_LEN;
    libspdm_copy_mem (interface_report->device_specific_info,
                      sizeof(interface_report->device_specific_info),
                      "tdisp_dev_emu",
                      sizeof("tdisp_dev_emu"));

    return PCI_TDISP_ERROR_CODE_SUCCESS;
}
