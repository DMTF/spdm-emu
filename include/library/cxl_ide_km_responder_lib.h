/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_IDE_KM_RESPONDER_LIB_H__
#define __CXL_IDE_KM_RESPONDER_LIB_H__

#include "library/pci_doe_responder_lib.h"
#include "library/cxl_ide_km_common_lib.h"

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response (const void *pci_doe_context,
                                          const void *spdm_context, const uint32_t *session_id,
                                          const void *request, size_t request_size,
                                          void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
typedef
    libspdm_return_t
(* cxl_ide_km_get_response_func_t) (const void *pci_doe_context,
                                    const void *spdm_context, const uint32_t *session_id,
                                    const void *request, size_t request_size,
                                    void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response_query (const void *pci_doe_context,
                                                const void *spdm_context, const uint32_t *session_id,
                                                const void *request, size_t request_size,
                                                void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response_key_prog (const void *pci_doe_context,
                                                   const void *spdm_context, const uint32_t *session_id,
                                                   const void *request, size_t request_size,
                                                   void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response_key_set_go (const void *pci_doe_context,
                                                     const void *spdm_context, const uint32_t *session_id,
                                                     const void *request, size_t request_size,
                                                     void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response_key_set_stop (const void *pci_doe_context,
                                                       const void *spdm_context, const uint32_t *session_id,
                                                       const void *request, size_t request_size,
                                                       void *response, size_t *response_size);

/**
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from cxl_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from cxl_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t cxl_ide_km_get_response_get_key (const void *pci_doe_context,
                                                  const void *spdm_context, const uint32_t *session_id,
                                                  const void *request, size_t request_size,
                                                  void *response, size_t *response_size);

#endif
