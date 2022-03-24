/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PCI_DOE_RESPONDER_LIB_H__
#define __PCI_DOE_RESPONDER_LIB_H__

#include "library/pci_doe_common_lib.h"

/**
    Process the DOE request and return the response.

    @param request       the PCI_DOE request message, start from pci_doe_data_object_header_t.
    @param request_size  size in bytes of request.
    @param response      the PCI_DOE response message, start from pci_doe_data_object_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_doe_get_response_doe_request(const void *pci_doe_context,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the SPDM vendor defined request and return the response.

    @param request       the SPDM vendor defined request message, start from spdm_message_header_t.
    @param request_size  size in bytes of request.
    @param response      the SPDM vendor defined message, start from spdm_message_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_doe_get_response_spdm_vendor_defined_request(const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);


/* internal function only*/

/**
    Process the DOE request and return the response.

    @param request       the PCI_DOE request message, start from pci_doe_data_object_header_t.
    @param request_size  size in bytes of request.
    @param response      the PCI_DOE response message, start from pci_doe_data_object_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
typedef
return_status
(* pci_doe_get_response_func_t) (const void *pci_doe_context,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the DOE request and return the response.

    @param request       the PCI_DOE request message, start from pci_doe_data_object_header_t.
    @param request_size  size in bytes of request.
    @param response      the PCI_DOE response message, start from pci_doe_data_object_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_doe_get_response_discovery (const void *pci_doe_context,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the SPDM vendor defined request and return the response.

    @param request       the SPDM vendor defined request message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the SPDM vendor defined response message, start after pci_protocol_header_t, e.g. pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
typedef
return_status
(* pci_doe_get_spdm_vendor_response_func_t) (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the IDE_KM request and return the response.

    @param request       the IDE_KM request message, start from pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the IDE_KM response message, start from pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_ide_km_get_response (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the IDE_KM request and return the response.

    @param request       the IDE_KM request message, start from pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the IDE_KM response message, start from pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
typedef
return_status
(* pci_ide_km_get_response_func_t) (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

/**
    Process the IDE_KM request and return the response.

    @param request       the IDE_KM request message, start from pci_ide_km_header_t.
    @param request_size  size in bytes of request.
    @param response      the IDE_KM response message, start from pci_ide_km_header_t.
    @param response_size size in bytes of response.

    @retval RETURN_SUCCESS The request is processed and the response is returned.
    @return ERROR          The request is not processed.
**/
return_status pci_ide_km_get_response_query (const void *pci_doe_context,
    const void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size);

#endif
