/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

extern void *m_spdm_context;

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
return_status spdm_send_receive_get_measurement(void *spdm_context,
                                                const uint32_t *session_id)
{
    return_status status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;

    if (m_use_measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* request all at one time.*/

        request_attribute =
            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        measurement_record_length = sizeof(measurement_record);
        status = libspdm_get_measurement(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            m_use_slot_id & 0xF, NULL, &number_of_block,
            &measurement_record_length, measurement_record);
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else {
        request_attribute = m_use_measurement_attribute;

        /* 1. query the total number of measurements available.*/

        status = libspdm_get_measurement(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF, NULL, &number_of_blocks, NULL, NULL);
        if (RETURN_ERROR(status)) {
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
            measurement_record_length = sizeof(measurement_record);
            status = libspdm_get_measurement(
                spdm_context, session_id, request_attribute,
                index, m_use_slot_id & 0xF, NULL, &number_of_block,
                &measurement_record_length, measurement_record);
            if (RETURN_ERROR(status)) {
                continue;
            }
            received_number_of_block += 1;
        }
        if (received_number_of_block != number_of_blocks) {
            return RETURN_DEVICE_ERROR;
        }
    }

    return RETURN_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
return_status do_measurement_via_spdm(const uint32_t *session_id)
{
    return_status status;
    void *spdm_context;

    spdm_context = m_spdm_context;

    status = spdm_send_receive_get_measurement(spdm_context, session_id);
    if (RETURN_ERROR(status)) {
        return status;
    }
    return RETURN_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
