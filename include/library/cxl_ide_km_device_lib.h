/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __CXL_IDE_KM_DEVICE_LIB_H__
#define __CXL_IDE_KM_DEVICE_LIB_H__

#include "library/cxl_ide_km_responder_lib.h"

typedef struct {
    /* provision info from device */
    uint8_t port_index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t max_port_index;
    uint8_t caps;
    uint32_t ide_reg_buffer[CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT];
    uint32_t ide_reg_buffer_count;

    /* runtime data from host */
    uint8_t stream_id;
    /*
     * 00 = RX
     * 01 = TX
     */
    cxl_ide_km_aes_256_gcm_key_buffer_t key_buffer[2];
    bool is_key_prog[2];
    bool is_key_set_go[2];

} libcxlidekm_device_port_context;

libcxlidekm_device_port_context *libcxlidekm_initialize_device_port_context (
    uint8_t port_index
    );

libcxlidekm_device_port_context *libcxlidekm_get_device_port_context (
    uint8_t port_index
    );

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
libspdm_return_t cxl_ide_km_device_query (const void *pci_doe_context,
                                          const void *spdm_context, const uint32_t *session_id,
                                          uint8_t port_index, uint8_t *dev_func_num,
                                          uint8_t *bus_num, uint8_t *segment,
                                          uint8_t *max_port_index,
                                          uint8_t *caps,
                                          uint32_t **ide_reg_buffer,
                                          uint32_t *ide_reg_buffer_count);

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
libspdm_return_t cxl_ide_km_device_key_prog (const void *pci_doe_context,
                                             const void *spdm_context, const uint32_t *session_id,
                                             uint8_t stream_id, uint8_t key_sub_stream,
                                             uint8_t port_index,
                                             uint8_t *kp_ack_status,
                                             const cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer);

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
libspdm_return_t cxl_ide_km_device_key_set_go (const void *pci_doe_context,
                                               const void *spdm_context, const uint32_t *session_id,
                                               uint8_t stream_id, uint8_t key_sub_stream,
                                               uint8_t port_index);

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
libspdm_return_t cxl_ide_km_device_key_set_stop (const void *pci_doe_context,
                                                 const void *spdm_context,
                                                 const uint32_t *session_id,
                                                 uint8_t stream_id, uint8_t key_sub_stream,
                                                 uint8_t port_index);

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
libspdm_return_t cxl_ide_km_device_get_key (const void *pci_doe_context,
                                            const void *spdm_context, const uint32_t *session_id,
                                            uint8_t stream_id, uint8_t key_sub_stream,
                                            uint8_t port_index,
                                            cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer);

#endif
