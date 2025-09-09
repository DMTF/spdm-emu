/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_requester_lib.h"

#pragma pack(1)
typedef struct {
    pci_tdisp_header_t header;
    uint16_t portion_length;
    uint16_t remainder_length;
    uint8_t report[LIBTDISP_INTERFACE_REPORT_PORTION_LEN];
} pci_tdisp_device_interface_report_response_mine_t;
#pragma pack()

/**
 * Send and receive a TDISP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The TDISP request is sent and response is received.
 * @return ERROR                        The TDISP response is not received correctly.
 **/
libspdm_return_t pci_tdisp_get_interface_report(const void *pci_doe_context,
                                                void *spdm_context, const uint32_t *session_id,
                                                const pci_tdisp_interface_id_t *interface_id,
                                                uint8_t *interface_report,
                                                uint32_t *interface_report_size)
{
    libspdm_return_t status;
    pci_tdisp_get_device_interface_report_request_t request;
    size_t request_size;
    pci_tdisp_device_interface_report_response_mine_t response;
    size_t response_size;
    uint16_t offset;
    uint16_t remainder_length;
    uint32_t total_report_length;

    offset = 0;
    remainder_length = 0;
    total_report_length = 0;
    do {
        libspdm_zero_mem (&request, sizeof(request));
        request.header.version = PCI_TDISP_MESSAGE_VERSION_10;
        request.header.message_type = PCI_TDISP_GET_DEVICE_INTERFACE_REPORT;
        request.header.interface_id.function_id = interface_id->function_id;
        request.offset = offset;
        request.length = LIBTDISP_INTERFACE_REPORT_PORTION_LEN;
        if (request.offset != 0) {
            request.length = LIBSPDM_MIN (remainder_length, LIBTDISP_INTERFACE_REPORT_PORTION_LEN);
        }

        request_size = sizeof(request);
        response_size = sizeof(response);
        status = pci_tdisp_send_receive_data(spdm_context, session_id,
                                             &request, request_size,
                                             &response, &response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        if (response_size < sizeof(pci_tdisp_device_interface_report_response_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response.portion_length > request.length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response_size !=
            sizeof(pci_tdisp_device_interface_report_response_t) + response.portion_length) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        if (response.header.version != request.header.version) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (response.header.message_type != PCI_TDISP_DEVICE_INTERFACE_REPORT) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (response.header.interface_id.function_id != request.header.interface_id.function_id) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if (offset == 0) {
            total_report_length = response.portion_length + response.remainder_length;
            if (total_report_length > *interface_report_size) {
                *interface_report_size = total_report_length;
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            if (total_report_length !=
                (uint32_t)(offset + response.portion_length + response.remainder_length)) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
        }
        libspdm_copy_mem (interface_report + offset,
                          *interface_report_size - offset,
                          response.report,
                          response.portion_length);
        offset = offset + response.portion_length;
        remainder_length = response.remainder_length;
    } while (remainder_length != 0);

    *interface_report_size = total_report_length;

    return LIBSPDM_STATUS_SUCCESS;
}
