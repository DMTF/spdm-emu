/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_TSP_DEVICE_LIB_H__
#define __CXL_TSP_DEVICE_LIB_H__

#include "library/cxl_tsp_responder_lib.h"

typedef struct {
    bool session_id_primary_valid;
    uint32_t session_id_primary;
    bool session_id_secondary_valid[CXL_TSP_2ND_SESSION_COUNT];
    uint32_t session_id_secondary[CXL_TSP_2ND_SESSION_COUNT];
    uint8_t supported_tsp_versions[1];
    uint8_t supported_tsp_versions_count;
    /* provision info from device */
    libcxltsp_device_capabilities_t device_capabilities;
    /* configuration to the device */
    libcxltsp_device_configuration_t device_configuration;
    /* 2nd session */
    libcxltsp_device_2nd_session_info_t device_2nd_session_info;
    /* runtime state */
    uint8_t current_tsp_state;

    uint8_t configuration_report[LIBCXLTSP_CONFIGURATION_REPORT_MAX_SIZE];
    uint16_t configuration_report_size;
} libcxltsp_device_context;

libcxltsp_device_context *libcxltsp_initialize_device_context (
    const void *pci_doe_context
    );

libcxltsp_device_context *libcxltsp_get_device_context (
    const void *pci_doe_context
    );

void libcxltsp_initialize_session_id (
    void *spdm_context,
    uint32_t session_id
    );

bool libcxltsp_is_session_primary (uint32_t session_id);
bool libcxltsp_is_session_secondary (uint32_t session_id);

typedef uint32_t libcxltsp_error_code_t;
#define CXL_TSP_ERROR_CODE_SUCCESS 0

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
libcxltsp_error_code_t cxl_tsp_device_get_version (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    uint8_t *version_number_entry_count,
    cxl_tsp_version_number_t *version_number_entry);

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
libcxltsp_error_code_t cxl_tsp_device_get_capabilities (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_capabilities_t *device_capabilities);

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
libcxltsp_error_code_t cxl_tsp_device_set_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const libcxltsp_device_configuration_t *device_configuration,
    const libcxltsp_device_2nd_session_info_t *device_2nd_session_info);

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
libcxltsp_error_code_t cxl_tsp_device_get_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_configuration_t *device_configuration,
    uint8_t *current_tsp_state);

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
    uint8_t **configuration_report, uint16_t *configuration_report_size);

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
libcxltsp_error_code_t cxl_tsp_device_lock_configuration (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id);

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
libcxltsp_error_code_t cxl_tsp_device_set_te_state (
    const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    uint8_t te_state,
    uint8_t number_of_memory_ranges,
    const cxl_tsp_memory_range_t *memory_ranges);

#endif
