/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
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
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id)
{
    libspdm_return_t status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;
    uint32_t data32;
    size_t data_size;
    bool need_sig;
    libspdm_data_parameter_t parameter;
    uint8_t requester_context[SPDM_REQ_CONTEXT_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00};
    bool measurement_exist_list[SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS] = {false};

    /*get requester_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) != 0) {
        need_sig = false;
    } else {
        need_sig = true;
    }

    if (m_use_measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* request all at one time.*/
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] =
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
        if (need_sig) {
            request_attribute =
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            request_attribute = 0;
        }
        measurement_record_length = sizeof(measurement_record);
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
            &measurement_record_length, measurement_record,
            NULL, NULL, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else {
        request_attribute = m_use_measurement_attribute;

        /* 1. query the total number of measurements available.*/
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] =
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_blocks, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n",
                       number_of_blocks));

        /* 2. get the existing measurement list*/
        received_number_of_block = 0;
        for (index = 1; index < SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS; index++) {
            if (received_number_of_block == number_of_blocks) {
                break;
            }
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "index - 0x%x\n", index));

            requester_context[SPDM_REQ_CONTEXT_SIZE - 1] = index;
            /* get signature in last message only.*/
            if (received_number_of_block == number_of_blocks - 1) {
                if (need_sig) {
                    request_attribute = m_use_measurement_attribute |
                                        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                } else {
                    request_attribute = m_use_measurement_attribute;
                }
            }
            measurement_record_length = sizeof(measurement_record);
            status = libspdm_get_measurement_ex2(
                spdm_context, session_id, request_attribute,
                index, m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
                &measurement_record_length, measurement_record,
                NULL, NULL, NULL, NULL, NULL);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                continue;
            }
            received_number_of_block++;
            measurement_exist_list[index] = true;
        }
        if (received_number_of_block != number_of_blocks) {
            return LIBSPDM_STATUS_INVALID_STATE_PEER;
        }

        /** 3. query measurement one by one
         *
         * In SPDM 1.2 spec, the L1/L2 will be reset in case of MEASUREMENT error. That impacts 1-by-1 calculation.
         * For example, if a device supports Measurement 1 and Measurement 3,
         * then our current mechanism will cause Measurement 1 NOT included in final transcript,
         * because Measurement 2 is missing.
         *
         * The soultion is: get the existing measurement list, then query measurement one by one.
         **/
        received_number_of_block = 0;
        for (index = 1; index < SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS; index++) {
            if (received_number_of_block == number_of_blocks) {
                break;
            }

            if (measurement_exist_list[index]) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "exist measurement index - 0x%x\n", index));
                
                requester_context[SPDM_REQ_CONTEXT_SIZE - 1] = index;
                /* get signature in last message only.*/
                if (received_number_of_block == number_of_blocks - 1) {
                    if (need_sig) {
                        request_attribute = m_use_measurement_attribute |
                                            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                    } else {
                        request_attribute = m_use_measurement_attribute;
                    }
                }
                measurement_record_length = sizeof(measurement_record);
                status = libspdm_get_measurement_ex2(
                    spdm_context, session_id, request_attribute,
                    index, m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
                    &measurement_record_length, measurement_record,
                    NULL, NULL, NULL, NULL, NULL);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return LIBSPDM_STATUS_ERROR_PEER;
                }
                received_number_of_block++;
            }
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;

    spdm_context = m_spdm_context;

    status = spdm_send_receive_get_measurement(spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement MEL.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_mel_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    libspdm_data_parameter_t parameter;
    uint32_t measurement_hash_algo;
    size_t data_size;

    spdm_context = m_spdm_context;
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    /* get setting from connection*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(measurement_hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &measurement_hash_algo, &data_size);

    status = libspdm_get_measurement_extension_log(spdm_context, session_id, &spdm_mel_size,
                                                   spdm_mel);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
