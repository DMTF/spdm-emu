/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_IDE_KM_REQUESTER_LIB_H__
#define __CXL_IDE_KM_REQUESTER_LIB_H__

#include "library/pci_doe_requester_lib.h"
#include "library/cxl_ide_km_common_lib.h"

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_query(const void *pci_doe_context,
                                  void *spdm_context, const uint32_t *session_id,
                                  uint8_t port_index, uint8_t *dev_func_num,
                                  uint8_t *bus_num, uint8_t *segment, uint8_t *max_port_index,
                                  uint8_t *caps,
                                  uint32_t *ide_reg_buffer, uint32_t *ide_reg_buffer_count);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_key_prog(const void *pci_doe_context,
                                     void *spdm_context, const uint32_t *session_id,
                                     uint8_t stream_id, uint8_t key_sub_stream, uint8_t port_index,
                                     const cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer,
                                     uint8_t *kp_ack_status);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_key_set_go(const void *pci_doe_context,
                                       void *spdm_context, const uint32_t *session_id,
                                       uint8_t stream_id, uint8_t key_sub_stream, uint8_t port_index);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_key_set_stop(const void *pci_doe_context,
                                         void *spdm_context, const uint32_t *session_id,
                                         uint8_t stream_id, uint8_t key_sub_stream, uint8_t port_index);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_get_key(const void *pci_doe_context,
                                    void *spdm_context, const uint32_t *session_id,
                                    uint8_t stream_id, uint8_t key_sub_stream, uint8_t port_index,
                                    cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer);

/**
 * Send and receive an IDE_KM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the IDE_KM request message, start from cxl_ide_km_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the IDE_KM response message, start from cxl_ide_km_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_ide_km_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

#endif
