/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_REQUESTER_LIB_H
#define PCI_TDISP_REQUESTER_LIB_H

#include "library/pci_doe_requester_lib.h"
#include "library/pci_tdisp_common_lib.h"

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_get_version(const void *pci_doe_context,
                                       void *spdm_context, const uint32_t *session_id,
                                       const pci_tdisp_interface_id_t *interface_id);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_get_capabilities(const void *pci_doe_context,
                                            void *spdm_context, const uint32_t *session_id,
                                            const pci_tdisp_interface_id_t *interface_id,
                                            const pci_tdisp_requester_capabilities_t *req_caps,
                                            pci_tdisp_responder_capabilities_t *rsp_caps);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_lock_interface(const void *pci_doe_context,
                                          void *spdm_context, const uint32_t *session_id,
                                          const pci_tdisp_interface_id_t *interface_id,
                                          const pci_tdisp_lock_interface_param_t *lock_interface_param,
                                          uint8_t *start_interface_nonce);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_get_interface_report(const void *pci_doe_context,
                                                void *spdm_context, const uint32_t *session_id,
                                                const pci_tdisp_interface_id_t *interface_id,
                                                uint8_t *interface_report,
                                                uint32_t *interface_report_size);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_get_interface_state(const void *pci_doe_context,
                                               void *spdm_context, const uint32_t *session_id,
                                               const pci_tdisp_interface_id_t *interface_id,
                                               uint8_t *tdi_state);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_start_interface(const void *pci_doe_context,
                                           void *spdm_context, const uint32_t *session_id,
                                           const pci_tdisp_interface_id_t *interface_id,
                                           const uint8_t *start_interface_nonce);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_stop_interface(const void *pci_doe_context,
                                          void *spdm_context, const uint32_t *session_id,
                                          const pci_tdisp_interface_id_t *interface_id);

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the TDISP request message, start from pci_tdisp_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the TDISP response message, start from pci_tidsp_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

#endif
