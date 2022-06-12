/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_attester_sample.h"

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id,
                                                   uint8_t *measurement_record,
                                                   uint32_t *measurement_record_length
                                                   )
{
    libspdm_return_t status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t one_measurement_record_length;
    uint8_t one_measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;
    uint32_t measurement_record_offset;

    /* request all at one time.*/

    request_attribute =
            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    status = libspdm_get_measurement(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            m_use_slot_id & 0xF, NULL, &number_of_block,
            measurement_record_length, measurement_record);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        return status;
    }

    /* use one by one */
    measurement_record_offset = 0;
    request_attribute = m_use_measurement_attribute;

    /* 1. query the total number of measurements available.*/

    status = libspdm_get_measurement(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF, NULL, &number_of_blocks, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n",
                       number_of_blocks));
    received_number_of_block = 0;
    for (index = 1; index <= 0xFE; index++) {
        if (received_number_of_block == number_of_blocks) {
            break;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "index - 0x%x\n", index));

        /* 2. query measurement one by one
         * get signature in last message only.*/

        if (received_number_of_block == number_of_blocks - 1) {
            request_attribute = m_use_measurement_attribute |
                                    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        }
        one_measurement_record_length = sizeof(one_measurement_record);
        status = libspdm_get_measurement(
                spdm_context, session_id, request_attribute,
                index, m_use_slot_id & 0xF, NULL, &number_of_block,
                &one_measurement_record_length, one_measurement_record);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            continue;
        }
        received_number_of_block += 1;

        LIBSPDM_ASSERT (*measurement_record_length >= measurement_record_offset);

        if (one_measurement_record_length < *measurement_record_length - measurement_record_offset) {
            libspdm_copy_mem (measurement_record + measurement_record_offset,
                              *measurement_record_length - measurement_record_offset,
                              one_measurement_record,
                              one_measurement_record_length);
            measurement_record_offset += one_measurement_record_length;
        } else {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
    }
    if (received_number_of_block != number_of_blocks) {
        return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }

    *measurement_record_length = measurement_record_offset;

    return LIBSPDM_STATUS_SUCCESS;
}
