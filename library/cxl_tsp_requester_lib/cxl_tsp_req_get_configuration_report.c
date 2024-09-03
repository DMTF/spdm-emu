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
    uint16_t portion_length;
    uint16_t remainder_length;
    uint8_t report[LIBCXLTSP_CONFIGURATION_REPORT_PORTION_LEN];
} cxl_tsp_get_target_configuration_report_rsp_mine_t;
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
libspdm_return_t cxl_tsp_get_configuration_report(
    const void *pci_doe_context,
    void *spdm_context, const uint32_t *session_id,
    uint8_t *configuration_report, uint32_t *configuration_report_size)
{
    libspdm_return_t status;
    cxl_tsp_get_target_configuration_report_req_t request;
    size_t request_size;
    cxl_tsp_get_target_configuration_report_rsp_mine_t response;
    size_t response_size;
    uint16_t offset;
    uint16_t remainder_length;
    uint32_t total_report_length;

    offset = 0;
    remainder_length = 0;
    total_report_length = 0;
    do {
        libspdm_zero_mem (&request, sizeof(request));
        request.header.tsp_version = CXL_TSP_MESSAGE_VERSION_10;
        request.header.op_code = CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT;
        request.offset = offset;
        request.length = LIBCXLTSP_CONFIGURATION_REPORT_PORTION_LEN;
        if (request.offset != 0) {
            request.length = LIBSPDM_MIN (remainder_length, LIBCXLTSP_CONFIGURATION_REPORT_PORTION_LEN);
        }

        request_size = sizeof(request);
        response_size = sizeof(response);
        status = cxl_tsp_send_receive_data(spdm_context, session_id,
                                        &request, request_size,
                                        &response, &response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        if (response_size < sizeof(cxl_tsp_get_target_configuration_report_rsp_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response.portion_length > request.length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response_size !=
            sizeof(cxl_tsp_get_target_configuration_report_rsp_t) + response.portion_length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response.header.tsp_version != request.header.tsp_version) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (response.header.op_code != CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT_RSP) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if (offset == 0) {
            total_report_length = response.portion_length + response.remainder_length;
            if (total_report_length > *configuration_report_size) {
                *configuration_report_size = total_report_length;
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            if (total_report_length !=
                (uint32_t)(offset + response.portion_length + response.remainder_length)) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
        }
        libspdm_copy_mem (configuration_report + offset,
                          *configuration_report_size - offset,
                          response.report,
                          response.portion_length);
        offset = offset + response.portion_length;
        remainder_length = response.remainder_length;
    } while (remainder_length != 0);

    *configuration_report_size = total_report_length;

    return LIBSPDM_STATUS_SUCCESS;
}
