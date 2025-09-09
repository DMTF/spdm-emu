/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_device_lib.h"

#pragma pack(1)
typedef struct {
    uint8_t valid_tsp_report_fields;
    uint8_t reserved[3];
    uint8_t pcie_dvsec_for_cxl_devices[0x3c];
    uint8_t pcie_dvsec_for_flex_bus_port[0x20];
    uint8_t cxl_link_capability_structure[0x38];
    uint8_t cxl_timeout_and_isolation_capability_structure[0x10];
    uint8_t cxl_hdm_decoder_capability_structure[0x10];
    /* uint8_t cxl_hdm_decoder[0x1f][decoder_count]; */
    uint8_t cxl_ide_capability_structure[0x24];
} cxl_tsp_target_configuration_report_mine_t;
#pragma pack()

/**
 *  Process the TSP request and return the response.
 *
 *  @param request       the TSP request message, start from cxl_tsp_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the TSP response message, start from cxl_tsp_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libcxltsp_error_code_t cxl_tsp_device_get_configuration_report (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    uint8_t **configuration_report, uint16_t *configuration_report_size)
{
    libcxltsp_device_context *device_context;
    cxl_tsp_target_configuration_report_mine_t *report;

    device_context = libcxltsp_get_device_context (pci_doe_context);
    if (device_context == NULL) {
        return CXL_TSP_ERROR_CODE_UNSPECIFIED;
    }

    report = (cxl_tsp_target_configuration_report_mine_t *)device_context->configuration_report;
    // TBD: fill hardware data
    report->valid_tsp_report_fields = 1;
    device_context->configuration_report_size = sizeof(cxl_tsp_target_configuration_report_mine_t);

    *configuration_report_size = device_context->configuration_report_size;
    *configuration_report = device_context->configuration_report;

    return CXL_TSP_ERROR_CODE_SUCCESS;
}
