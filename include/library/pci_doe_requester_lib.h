/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __PCI_DOE_REQUESTER_LIB_H__
#define __PCI_DOE_REQUESTER_LIB_H__

#include "library/pci_doe_common_lib.h"

libspdm_return_t pci_doe_discovery (const void *pci_doe_context,
                                 pci_doe_data_object_protocol_t *data_object_protocol,
                                 size_t *data_object_protocol_size);

libspdm_return_t pci_ide_km_query(const void *pci_doe_context,
                               void *spdm_context, const uint32_t *session_id,
                               uint8_t port_index, uint8_t *max_port_index);

/* external provided function */

/**
 * Send and receive an DOE message
 *
 * @param request                       the PCI DOE request message, start from pci_doe_data_object_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PCI DOE response message, start from pci_doe_data_object_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The request is sent and response is received.
 * @return ERROR                        The response is not received correctly.
 **/
libspdm_return_t pci_doe_send_receive_data(const void *pci_doe_context,
                                        size_t request_size, const void *request,
                                        size_t *response_size, void *response);


/* internal function only*/

/**
 * Send and receive an SPDM vendor defined message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the SPDM vendor defined request message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the SPDM vendor defined response message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The SPDM vendor defined request is sent and response is received.
 * @return ERROR                        The SPDM vendor defined response is not received correctly.
 **/
libspdm_return_t pci_doe_spdm_vendor_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    pci_protocol_header_t pci_protocol,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the IDE_KM request message, start from pci_ide_km_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the IDE_KM response message, start from pci_ide_km_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t ide_km_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

#endif
