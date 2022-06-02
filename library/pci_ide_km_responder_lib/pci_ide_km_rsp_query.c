/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_ide_km_device_lib.h"

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
 *  Process the IDE_KM request and return the response.
 *
 *  @param request       the IDE_KM request message, start from pci_ide_km_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the IDE_KM response message, start from pci_ide_km_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t pci_ide_km_get_response_query (const void *pci_doe_context,
                                                const void *spdm_context, const uint32_t *session_id,
                                                const void *request, size_t request_size,
                                                void *response, size_t *response_size)
{
    const pci_ide_km_query_t *ide_km_request;
    pci_ide_km_query_resp_mine_t *ide_km_response;
    libspdm_return_t status;
    uint32_t *ide_reg_buffer;
    uint32_t ide_reg_buffer_count;

    ide_km_request = request;
    ide_km_response = response;
    if (request_size != sizeof(pci_ide_km_query_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size >= sizeof(pci_ide_km_query_resp_mine_t));
    *response_size = sizeof(pci_ide_km_query_resp_mine_t);

    libspdm_zero_mem (response, *response_size);
    ide_km_response->header.object_id = PCI_IDE_KM_OBJECT_ID_QUERY_RESP;

    status = pci_ide_km_device_query (pci_doe_context, spdm_context, session_id,
                                      ide_km_request->port_index,
                                      &ide_km_response->dev_func_num,
                                      &ide_km_response->bus_num,
                                      &ide_km_response->segment,
                                      &ide_km_response->max_port_index,
                                      &ide_reg_buffer, &ide_reg_buffer_count);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (ide_reg_buffer_count <= PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT);
    libspdm_copy_mem (ide_km_response->ide_reg_block,
                      sizeof(ide_km_response->ide_reg_block),
                      ide_reg_buffer,
                      ide_reg_buffer_count * sizeof(uint32_t));

    *response_size = sizeof(pci_ide_km_query_resp_t) + ide_reg_buffer_count * sizeof(uint32_t);

    return LIBSPDM_STATUS_SUCCESS;
}
