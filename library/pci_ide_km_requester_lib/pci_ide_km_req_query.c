/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_ide_km_requester_lib.h"

#pragma pack(1)
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t max_port_index;
    uint32_t ide_reg_block[PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT];
} pci_ide_km_query_resp_mine_t;
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
libspdm_return_t pci_ide_km_query(const void *pci_doe_context,
                                  void *spdm_context, const uint32_t *session_id,
                                  uint8_t port_index, uint8_t *dev_func_num,
                                  uint8_t *bus_num, uint8_t *segment, uint8_t *max_port_index,
                                  uint32_t *ide_reg_buffer, uint32_t *ide_reg_buffer_count)
{
    libspdm_return_t status;
    pci_ide_km_query_t request;
    size_t request_size;
    pci_ide_km_query_resp_mine_t response;
    size_t response_size;
    uint32_t ide_reg_count;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.object_id = PCI_IDE_KM_OBJECT_ID_QUERY;
    request.port_index = port_index;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = pci_ide_km_send_receive_data(spdm_context, session_id,
                                          &request, request_size,
                                          &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (response_size < sizeof(pci_ide_km_query_resp_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    ide_reg_count = (uint32_t)(response_size - sizeof(pci_ide_km_query_resp_t)) / sizeof(uint32_t);
    if (response_size != sizeof(pci_ide_km_query_resp_t) + ide_reg_count * sizeof(uint32_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (response.header.object_id != PCI_IDE_KM_OBJECT_ID_QUERY_RESP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (response.port_index != request.port_index) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (*ide_reg_buffer_count < ide_reg_count) {
        *ide_reg_buffer_count = ide_reg_count;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    *dev_func_num= response.dev_func_num;
    *bus_num= response.bus_num;
    *segment= response.segment;
    *max_port_index= response.max_port_index;
    libspdm_copy_mem (ide_reg_buffer,
                      *ide_reg_buffer_count * sizeof(uint32_t),
                      response.ide_reg_block,
                      ide_reg_count * sizeof(uint32_t)
                      );
    *ide_reg_buffer_count = ide_reg_count;

    return LIBSPDM_STATUS_SUCCESS;
}
