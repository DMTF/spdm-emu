/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __MCTP_RESPONDER_LIB_H__
#define __MCTP_RESPONDER_LIB_H__

#include "library/mctp_common_lib.h"

/**
 *  Process the MCTP request and return the response.
 *
 *  @param request       the MCTP request message, start from mctp_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the MCTP response message, start from mctp_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t mctp_get_response_secured_app_request(const void *mctp_context,
                                                    void *spdm_context, const uint32_t *session_id,
                                                    const void *request, size_t request_size,
                                                    void *response, size_t *response_size);

/* internal function only*/

/**
 *  Process the MCTP request and return the response.
 *
 *  @param request       the MCTP request message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the MCTP response message, start after mctp_message_header_t, e.g. pldm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
typedef
    libspdm_return_t
(* mctp_get_secured_app_request_func_t) (const void *mctp_context,
                                         const void *spdm_context, const uint32_t *session_id,
                                         const void *request, size_t request_size,
                                         void *response, size_t *response_size);

/**
 *  Process the PLDM request and return the response.
 *
 *  @param request       the PLDM request message, start from pldm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the PLDM response message, start from pldm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pldm_get_response_secured_app_request (const void *mctp_context,
                                                     const void *spdm_context,
                                                     const uint32_t *session_id,
                                                     const void *request, size_t request_size,
                                                     void *response, size_t *response_size);

/**
 *  Process the PLDM request and return the response.
 *
 *  @param request       the PLDM request message, start from pldm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the PLDM response message, start from pldm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
typedef
    libspdm_return_t
(* pldm_get_secured_app_request_func_t) (const void *mctp_context,
                                         const void *spdm_context, const uint32_t *session_id,
                                         const void *request, size_t request_size,
                                         void *response, size_t *response_size);

/**
 *  Process the PLDM request and return the response.
 *
 *  @param request       the PLDM request message, start from pldm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the PLDM response message, start from pldm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pldm_get_response_control_get_tid (const void *mctp_context,
                                                 const void *spdm_context,
                                                 const uint32_t *session_id,
                                                 const void *request, size_t request_size,
                                                 void *response, size_t *response_size);

#endif
