/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_ide_km_requester_lib.h"

#pragma pack(1)
typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    cxl_ide_km_aes_256_gcm_key_buffer_t key_buffer;
} cxl_ide_km_get_key_ack_mine_t;
#pragma pack()

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
                                    cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer)
{
    libspdm_return_t status;
    cxl_ide_km_get_key_t request;
    size_t request_size;
    cxl_ide_km_get_key_ack_mine_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.object_id = CXL_IDE_KM_OBJECT_ID_GET_KEY;
    request.stream_id = stream_id;
    request.key_sub_stream = key_sub_stream;
    request.port_index = port_index;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = cxl_ide_km_send_receive_data(spdm_context, session_id,
                                          &request, request_size,
                                          &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(cxl_ide_km_get_key_ack_mine_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response.header.object_id != CXL_IDE_KM_OBJECT_ID_GET_KEY_ACK) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.stream_id != request.stream_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.key_sub_stream != request.key_sub_stream) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.port_index != request.port_index) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    libspdm_copy_mem (key_buffer, sizeof(cxl_ide_km_aes_256_gcm_key_buffer_t),
                      &response.key_buffer, sizeof(response.key_buffer));
    libspdm_zero_mem (&response.key_buffer, sizeof(response.key_buffer));

    return LIBSPDM_STATUS_SUCCESS;
}
