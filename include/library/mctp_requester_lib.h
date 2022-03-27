/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __MCTP_REQUESTER_LIB_H__
#define __MCTP_REQUESTER_LIB_H__

#include "library/mctp_common_lib.h"

libspdm_return_t pldm_control_get_tid(const void *mctp_context,
                                   void *spdm_context, const uint32_t *session_id, uint8_t *tid);

/* internal function only*/

/**
 * Send and receive an MCTP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the MCTP request message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the MCTP response message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The MCTP request is sent and response is received.
 * @return ERROR                        The MCTP response is not received correctly.
 **/
libspdm_return_t mctp_send_receive_data (const void *mctp_context,
                                      void *spdm_context, const uint32_t *session_id,
                                      mctp_message_header_t mctp_header,
                                      const void *request, size_t request_size,
                                      void *response, size_t *response_size);

/**
 * Send and receive an PLDM message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the PLDM request message, start from pldm_message_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PLDM response message, start from pldm_message_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The PLDM request is sent and response is received.
 * @return ERROR                        The PLDM response is not received correctly.
 **/
libspdm_return_t pldm_send_receive_data (const void *mctp_context,
                                      void *spdm_context, const uint32_t *session_id,
                                      const void *request, size_t request_size,
                                      void *response, size_t *response_size);

#endif
