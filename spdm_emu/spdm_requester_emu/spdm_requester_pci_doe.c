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

libspdm_return_t pci_tdisp_process_session_message(void *spdm_context, uint32_t session_id)
{
    pci_tdisp_interface_id_t interface_id;
    libspdm_return_t status;
    size_t index;
    pci_tdisp_requester_capabilities_t req_caps;
    pci_tdisp_responder_capabilities_t rsp_caps;
    pci_tdisp_lock_interface_param_t lock_interface_param;
    uint8_t start_interface_nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
    uint8_t tdi_state;
    uint8_t interface_report_buffer[LIBTDISP_INTERFACE_REPORT_MAX_SIZE];
    uint32_t interface_report_size;
    pci_tdisp_device_interface_report_struct_t *interface_report;
    pci_tdisp_mmio_range_t *mmio_range;
    uint32_t *device_specific_info_len;
    uint8_t *device_specific_info;

    interface_id.function_id = 0xbeef;
    interface_id.reserved = 0;
    status = pci_tdisp_get_version (m_pci_doe_context, spdm_context, &session_id, &interface_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "get_version done\n"));

    req_caps.tsm_caps = 0;
    libspdm_zero_mem (&rsp_caps, sizeof(rsp_caps));
    status = pci_tdisp_get_capabilities (m_pci_doe_context, spdm_context, &session_id,
                                         &interface_id,
                                         &req_caps, &rsp_caps);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "rsp_caps:\n"));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  dsm_caps - 0x%08x\n", rsp_caps.dsm_caps));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  req_msg_supported - %02x %02x\n",
                   rsp_caps.req_msg_supported[0], rsp_caps.req_msg_supported[1]));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  lock_interface_flags_supported - 0x%04x\n",
                   rsp_caps.lock_interface_flags_supported));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  dev_addr_width - 0x%02x\n", rsp_caps.dev_addr_width));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  num_req_this - 0x%02x\n", rsp_caps.num_req_this));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  num_req_all - 0x%02x\n", rsp_caps.num_req_all));

    status = pci_tdisp_get_interface_state (m_pci_doe_context, spdm_context, &session_id,
                                            &interface_id,
                                            &tdi_state);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "tdi_state: 0x%02x\n", tdi_state));
    LIBSPDM_ASSERT (tdi_state == PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED);

    libspdm_zero_mem (&lock_interface_param, sizeof(lock_interface_param));
    lock_interface_param.flags = rsp_caps.lock_interface_flags_supported;
    lock_interface_param.default_stream_id = 0;
    lock_interface_param.mmio_reporting_offset = 0xD0000000;
    lock_interface_param.bind_p2p_address_mask = 0;
    libspdm_zero_mem (&start_interface_nonce, sizeof(start_interface_nonce));
    status = pci_tdisp_lock_interface (m_pci_doe_context, spdm_context, &session_id, &interface_id,
                                       &lock_interface_param, start_interface_nonce);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "start_interface_nonce: "));
    for (index = 0; index < sizeof(start_interface_nonce); index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x ", start_interface_nonce[index]));
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    status = pci_tdisp_get_interface_state (m_pci_doe_context, spdm_context, &session_id,
                                            &interface_id,
                                            &tdi_state);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "tdi_state: 0x%02x\n", tdi_state));
    LIBSPDM_ASSERT (tdi_state == PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED);

    interface_report_size = sizeof(interface_report_buffer);
    status = pci_tdisp_get_interface_report (m_pci_doe_context, spdm_context, &session_id,
                                             &interface_id,
                                             interface_report_buffer, &interface_report_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    interface_report = (pci_tdisp_device_interface_report_struct_t *)interface_report_buffer;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "interface_report:\n"));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  interface_info        - 0x%04x\n",
                   interface_report->interface_info));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  msi_x_message_control - 0x%04x\n",
                   interface_report->msi_x_message_control));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  lnr_control           - 0x%04x\n",
                   interface_report->lnr_control));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  tph_control           - 0x%08x\n",
                   interface_report->tph_control));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  mmio_range_count      - 0x%08x\n",
                   interface_report->mmio_range_count));
    mmio_range = (pci_tdisp_mmio_range_t *)(interface_report + 1);
    for (index = 0; index < interface_report->mmio_range_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  mmio_range(%d):\n", index));
#ifdef _MSC_VER
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "    first_page          - 0x%016I64x\n",
                       mmio_range[index].first_page));
#else
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "    first_page          - 0x%016llx\n",
                       mmio_range[index].first_page));
#endif
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "    number_of_pages     - 0x%08x\n",
                       mmio_range[index].number_of_pages));
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "    range_attributes    - 0x%04x\n",
                       mmio_range[index].range_attributes));
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "    range_id            - 0x%04x\n",
                       mmio_range[index].range_id));
    }
    device_specific_info_len = (uint32_t *)&mmio_range[index];
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  device_info_len       - 0x%08x\n",
                   *device_specific_info_len));
    device_specific_info = (uint8_t *)(device_specific_info_len + 1);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "  device_info           - "));
    for (index = 0; index < *device_specific_info_len; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x ", device_specific_info[index]));
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    status = pci_tdisp_start_interface (m_pci_doe_context, spdm_context, &session_id, &interface_id,
                                        start_interface_nonce);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "start_interface done\n"));

    status = pci_tdisp_get_interface_state (m_pci_doe_context, spdm_context, &session_id,
                                            &interface_id,
                                            &tdi_state);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "tdi_state: 0x%02x\n", tdi_state));
    LIBSPDM_ASSERT (tdi_state == PCI_TDISP_INTERFACE_STATE_RUN);

    status = pci_tdisp_stop_interface (m_pci_doe_context, spdm_context, &session_id, &interface_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "stop_interface done\n"));

    status = pci_tdisp_get_interface_state (m_pci_doe_context, spdm_context, &session_id,
                                            &interface_id,
                                            &tdi_state);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "tdi_state: 0x%02x\n", tdi_state));
    LIBSPDM_ASSERT (tdi_state == PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED);

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t cxl_ide_km_process_session_message(void *spdm_context, uint32_t session_id)
{
    uint8_t max_port_index;
    libspdm_return_t status;
    uint8_t index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t caps;
    uint32_t ide_reg_block[CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT];
    uint32_t ide_reg_block_count;
    cxl_ide_km_aes_256_gcm_key_buffer_t key_buffer;
    uint8_t kp_ack_status;
    bool result;

    caps = 0;
    ide_reg_block_count = CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT;
    status = cxl_ide_km_query (m_pci_doe_context, spdm_context, &session_id,
                               0, &dev_func_num, &bus_num, &segment, &max_port_index,
                               &caps,
                               ide_reg_block, &ide_reg_block_count);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "max_port_index - 0x%02x\n", max_port_index));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "caps - 0x%02x\n", caps));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ide_reg_block:\n"));
    for (index = 0; index < ide_reg_block_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04x: 0x%08x\n", index, ide_reg_block[index]));
    }

    status = cxl_ide_km_get_key(m_pci_doe_context, spdm_context, &session_id,
                                0, CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0,
                                &key_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "get_key\n"));

    status = cxl_ide_km_key_prog (m_pci_doe_context, spdm_context, &session_id,
                                  0, CXL_IDE_KM_KEY_DIRECTION_RX | CXL_IDE_KM_KEY_IV_INITIAL |
                                  CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0,
                                  &key_buffer, &kp_ack_status);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_prog RX - %02x\n", kp_ack_status));

    result = libspdm_get_random_number(sizeof(key_buffer.key), (void *)key_buffer.key);
    if (!result) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    key_buffer.iv[0] = 0;
    key_buffer.iv[1] = 1;
    key_buffer.iv[2] = 2;
    status = cxl_ide_km_key_prog (m_pci_doe_context, spdm_context, &session_id,
                                  0, CXL_IDE_KM_KEY_DIRECTION_TX | CXL_IDE_KM_KEY_IV_INITIAL |
                                  CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0,
                                  &key_buffer, &kp_ack_status);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_prog TX - %02x\n", kp_ack_status));

    status = cxl_ide_km_key_set_go (m_pci_doe_context, spdm_context, &session_id,
                                    0, CXL_IDE_KM_KEY_DIRECTION_RX | CXL_IDE_KM_KEY_MODE_SKID |
                                    CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_go RX\n"));

    status = cxl_ide_km_key_set_go (m_pci_doe_context, spdm_context, &session_id,
                                    0, CXL_IDE_KM_KEY_DIRECTION_TX | CXL_IDE_KM_KEY_MODE_SKID |
                                    CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_go TX\n"));


    status = cxl_ide_km_key_set_stop (m_pci_doe_context, spdm_context, &session_id,
                                      0, CXL_IDE_KM_KEY_DIRECTION_RX |
                                      CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_stop RX\n"));

    status = cxl_ide_km_key_set_stop (m_pci_doe_context, spdm_context, &session_id,
                                      0, CXL_IDE_KM_KEY_DIRECTION_TX |
                                      CXL_IDE_KM_KEY_SUB_STREAM_CXL, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_set_stop TX\n"));

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t pci_doe_process_session_message(void *spdm_context, uint32_t session_id)
{
    libspdm_return_t status;

    status = pci_ide_km_process_session_message (spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    status = pci_tdisp_process_session_message (spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    status = cxl_ide_km_process_session_message (spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
