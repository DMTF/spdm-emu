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

/**
 * Send and receive an TSP message
 *
 * @param  spdm_context                 A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param request                       the TSP request message, start from cxl_tsp_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the TSP response message, start from cxl_tsp_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The IDM_KM request is sent and response is received.
 * @return ERROR                        The IDM_KM response is not received correctly.
 **/
libspdm_return_t cxl_tsp_send_receive_data (
    void *spdm_context, const uint32_t *session_id,
    const void *request, size_t request_size,
    void *response, size_t *response_size)
{
    libspdm_return_t status;
    cxl_protocol_header_t cxl_protocol;

    cxl_protocol.protocol_id = CXL_PROTOCOL_ID_TSP;
    status = pci_doe_spdm_vendor_send_receive_data_ex (spdm_context, session_id,
                                                       SPDM_VENDOR_ID_CXL, cxl_protocol,
                                                       request, request_size, response,
                                                       response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
