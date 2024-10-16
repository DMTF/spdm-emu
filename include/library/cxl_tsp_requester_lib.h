/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_TSP_REQUESTER_LIB_H__
#define __CXL_TSP_REQUESTER_LIB_H__

#include "library/pci_doe_requester_lib.h"
#include "library/cxl_tsp_common_lib.h"

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_version(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_capabilities(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_capabilities_t *device_capabilities);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_set_configuration(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    const libcxltsp_device_configuration_t *device_configuration,
    const libcxltsp_device_2nd_session_info_t *device_2nd_session_info);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_configuration(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    libcxltsp_device_configuration_t *device_configuration,
    uint8_t *current_tsp_state);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_configuration_report(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    uint8_t *configuration_report, uint32_t *configuration_report_size);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_lock_configuration(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_set_te_state(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    uint8_t te_state,
    uint8_t number_of_memory_ranges,
    const cxl_tsp_memory_range_t *memory_ranges);

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the TSP request message, start from cxl_tsp_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the TSP response message, start from cxl_tsp_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

#endif
