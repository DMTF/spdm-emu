/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_RESPONDER_LIB_H
#define PCI_TDISP_RESPONDER_LIB_H

#include "library/pci_doe_responder_lib.h"
#include "library/pci_tdisp_common_lib.h"

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
libspdm_return_t pci_tdisp_get_response (const void *pci_doe_context,
                                         const void *spdm_context, const uint32_t *session_id,
                                         const void *request, size_t request_size,
                                         void *response, size_t *response_size);

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
typedef
    libspdm_return_t
(* pci_tdisp_get_response_func_t) (const void *pci_doe_context,
                                   const void *spdm_context, const uint32_t *session_id,
                                   const void *request, size_t request_size,
                                   void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_version (const void *pci_doe_context,
                                                 const void *spdm_context,
                                                 const uint32_t *session_id,
                                                 const void *request, size_t request_size,
                                                 void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_capabilities (const void *pci_doe_context,
                                                      const void *spdm_context,
                                                      const uint32_t *session_id,
                                                      const void *request, size_t request_size,
                                                      void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_lock_interface (const void *pci_doe_context,
                                                        const void *spdm_context,
                                                        const uint32_t *session_id,
                                                        const void *request, size_t request_size,
                                                        void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_interface_report (const void *pci_doe_context,
                                                          const void *spdm_context,
                                                          const uint32_t *session_id,
                                                          const void *request, size_t request_size,
                                                          void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_interface_state (const void *pci_doe_context,
                                                         const void *spdm_context,
                                                         const uint32_t *session_id,
                                                         const void *request, size_t request_size,
                                                         void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_start_interface (const void *pci_doe_context,
                                                         const void *spdm_context,
                                                         const uint32_t *session_id,
                                                         const void *request, size_t request_size,
                                                         void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_stop_interface (const void *pci_doe_context,
                                                        const void *spdm_context,
                                                        const uint32_t *session_id,
                                                        const void *request, size_t request_size,
                                                        void *response, size_t *response_size);

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
libspdm_return_t pci_tdisp_get_response_error (const void *pci_doe_context,
                                               const void *spdm_context, const uint32_t *session_id,
                                               const pci_tdisp_header_t *tdisp_header,
                                               uint32_t error_code, uint32_t error_data,
                                               void *response, size_t *response_size);

#endif
