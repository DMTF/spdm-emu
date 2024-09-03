/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/cxl_tsp_requester_lib.h"

#pragma pack(1)
typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint8_t version_number_entry_count;
    cxl_tsp_version_number_t version_number_entry[1];
} cxl_tsp_get_target_tsp_version_rsp_mine_t;
#pragma pack()

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TSP request is sent and response is received.
 * @return ERROR                        The TSP response is not received correctly.
 **/
libspdm_return_t cxl_tsp_get_version(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id)
{
    libspdm_return_t status;
    cxl_tsp_get_target_tsp_version_req_t request;
    size_t request_size;
    cxl_tsp_get_target_tsp_version_rsp_mine_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.tsp_version = CXL_TSP_MESSAGE_VERSION_10;
    request.header.op_code = CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = cxl_tsp_send_receive_data(spdm_context, session_id,
                                       &request, request_size,
                                       &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size != sizeof(cxl_tsp_get_target_tsp_version_rsp_mine_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (response.header.tsp_version != request.header.tsp_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.header.op_code != CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION_RSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (response.version_number_entry_count != 1) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.version_number_entry[0] != CXL_TSP_MESSAGE_VERSION_10) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
