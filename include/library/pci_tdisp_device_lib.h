/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_DEVICE_LIB_H
#define PCI_TDISP_DEVICE_LIB_H

#include "library/pci_tdisp_responder_lib.h"

typedef struct {
    /* provision info from device */
    pci_tdisp_interface_id_t interface_id;
    uint8_t supported_tdisp_versions[LIBTDISP_MAX_VERSION_COUNT];
    uint8_t supported_tdisp_versions_count;
    pci_tdisp_responder_capabilities_t tdisp_rsp_caps;

    /* runtime data from host */
    uint8_t tdisp_version;
    pci_tdisp_requester_capabilities_t tdisp_req_caps;
    pci_tdisp_lock_interface_param_t lock_interface_param;

    /* runtime device info */
    uint8_t tdi_state;
    uint8_t start_interface_nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
    uint8_t interface_report[LIBTDISP_INTERFACE_REPORT_MAX_SIZE];
    uint16_t interface_report_size;

} libtdisp_interface_context;

libtdisp_interface_context *libtdisp_initialize_interface_context (
    const pci_tdisp_interface_id_t *interface_id
    );

libtdisp_interface_context *libtdisp_get_interface_context (
    const pci_tdisp_interface_id_t *interface_id
    );

typedef uint32_t libtdisp_error_code_t;
#define PCI_TDISP_ERROR_CODE_SUCCESS 0
/* For rest, use PCI_TDISP_ERROR_CODE_xxx in TDISP specification */

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
libtdisp_error_code_t pci_tdisp_device_get_version (const void *pci_doe_context,
                                                    const void *spdm_context,
                                                    const uint32_t *session_id,
                                                    const pci_tdisp_interface_id_t *interface_id,
                                                    uint8_t *version_num_count,
                                                    pci_tdisp_version_number_t *version_num_entry);

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
libtdisp_error_code_t pci_tdisp_device_get_capabilities (const void *pci_doe_context,
                                                         const void *spdm_context,
                                                         const uint32_t *session_id,
                                                         const pci_tdisp_interface_id_t *interface_id,
                                                         const pci_tdisp_requester_capabilities_t *req_caps,
                                                         pci_tdisp_responder_capabilities_t *rsp_caps);

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
libtdisp_error_code_t pci_tdisp_device_lock_interface (const void *pci_doe_context,
                                                       const void *spdm_context,
                                                       const uint32_t *session_id,
                                                       const pci_tdisp_interface_id_t *interface_id,
                                                       const pci_tdisp_lock_interface_param_t *lock_interface_param,
                                                       uint8_t *start_interface_nonce);

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
libtdisp_error_code_t pci_tdisp_device_get_interface_report (const void *pci_doe_context,
                                                             const void *spdm_context,
                                                             const uint32_t *session_id,
                                                             const pci_tdisp_interface_id_t *interface_id,
                                                             uint8_t **interface_report, uint16_t *interface_report_size);

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
libtdisp_error_code_t pci_tdisp_device_get_interface_state (const void *pci_doe_context,
                                                            const void *spdm_context,
                                                            const uint32_t *session_id,
                                                            const pci_tdisp_interface_id_t *interface_id,
                                                            uint8_t *tdi_state);

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
libtdisp_error_code_t pci_tdisp_device_start_interface (const void *pci_doe_context,
                                                        const void *spdm_context,
                                                        const uint32_t *session_id,
                                                        const pci_tdisp_interface_id_t *interface_id,
                                                        const uint8_t *start_interface_nonce);

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
libtdisp_error_code_t pci_tdisp_device_stop_interface (const void *pci_doe_context,
                                                       const void *spdm_context,
                                                       const uint32_t *session_id,
                                                       const pci_tdisp_interface_id_t *interface_id);

#endif
