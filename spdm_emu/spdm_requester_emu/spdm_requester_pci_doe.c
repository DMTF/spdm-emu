/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

void *m_pci_doe_context;

libspdm_return_t pci_doe_init_requester()
{
    pci_doe_data_object_protocol_t data_object_protocol[6];
    size_t data_object_protocol_size;
    libspdm_return_t status;
    uint32_t index;

    data_object_protocol_size = sizeof(data_object_protocol);
    status =
        pci_doe_discovery (m_pci_doe_context, data_object_protocol, &data_object_protocol_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (index = 0; index < data_object_protocol_size/sizeof(pci_doe_data_object_protocol_t);
         index++) {
        printf("DOE(0x%x) VendorId-0x%04x, DataObjectType-0x%02x\n",
               index, data_object_protocol[index].vendor_id,
               data_object_protocol[index].data_object_type);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t pci_ide_km_process_session_message(void *spdm_context, uint32_t session_id)
{
    uint8_t max_port_index;
    libspdm_return_t status;
    uint8_t index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint32_t ide_reg_block[PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT];
    uint32_t ide_reg_block_count;
    pci_ide_km_aes_256_gcm_key_buffer_t key_buffer;
    uint8_t kp_ack_status;
    bool result;

    ide_reg_block_count = PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT;
    status = pci_ide_km_query (m_pci_doe_context, spdm_context, &session_id,
                               0, &dev_func_num, &bus_num, &segment, &max_port_index,
                               ide_reg_block, &ide_reg_block_count);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "max_port_index - 0x%02x\n", max_port_index));

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ide_reg_block:\n"));
    for (index = 0; index < ide_reg_block_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04x: 0x%08x\n", index, ide_reg_block[index]));
    }

    result = libspdm_get_random_number(sizeof(key_buffer.key), (void *)key_buffer.key);
    if (!result) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    key_buffer.iv[0] = 0;
    key_buffer.iv[1] = 1;
    status = pci_ide_km_key_prog (m_pci_doe_context, spdm_context, &session_id,
                                  0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX, 0,
                                  &key_buffer, &kp_ack_status);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_prog K0|RX - %02x\n", kp_ack_status));

    result = libspdm_get_random_number(sizeof(key_buffer.key), (void *)key_buffer.key);
    if (!result) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    key_buffer.iv[0] = 0;
    key_buffer.iv[1] = 1;
    status = pci_ide_km_key_prog (m_pci_doe_context, spdm_context, &session_id,
                                  0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX, 0,
                                  &key_buffer, &kp_ack_status);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_prog K0|TX - %02x\n", kp_ack_status));

    status = pci_ide_km_key_set_go (m_pci_doe_context, spdm_context, &session_id,
                                    0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_go K0|RX\n"));

    status = pci_ide_km_key_set_go (m_pci_doe_context, spdm_context, &session_id,
                                    0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_go K0|TX\n"));


    status = pci_ide_km_key_set_stop (m_pci_doe_context, spdm_context, &session_id,
                                      0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_stop K0|RX\n"));

    status = pci_ide_km_key_set_stop (m_pci_doe_context, spdm_context, &session_id,
                                      0, PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_stop K0|TX\n"));

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t pci_doe_process_session_message(void *spdm_context, uint32_t session_id)
{
    libspdm_return_t status;

    status = pci_ide_km_process_session_message (spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
