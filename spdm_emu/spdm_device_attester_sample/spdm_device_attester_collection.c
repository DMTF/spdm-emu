/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_attester_sample.h"

void
spdm_device_evidence_collection (void *spdm_context)
{
    libspdm_return_t status;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    spdm_attester_cert_chain_struct_t cert_chain;
    uint8_t slot_id;
    uint32_t session_id;
    char cert_chain_name[] = "device_cert_chain_0.bin";
    char measurement_name[] = "device_measurement.bin";

    /* get cert_chain 0 */
    slot_id = 0;
    cert_chain.cert_chain_size = sizeof(cert_chain.cert_chain);
    libspdm_zero_mem (cert_chain.cert_chain, sizeof(cert_chain.cert_chain));
    status = libspdm_get_certificate (spdm_context, NULL, slot_id,
                                      &cert_chain.cert_chain_size,
                                      cert_chain.cert_chain);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_get_certificate (slot=%d) - %x\n", slot_id, (uint32_t)status);
        return;
    }
    cert_chain_name[18] = slot_id + '0';
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "write file - %s\n", cert_chain_name));
    libspdm_write_output_file (cert_chain_name,
                               cert_chain.cert_chain,
                               cert_chain.cert_chain_size);

    /* setup session based on slot 0 */
    status = libspdm_start_session(
        spdm_context, false, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        0,
        SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE,
        &session_id,
        NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_start_session - %x\n", (uint32_t)status);
        return;
    }

    /* get measurement */
    measurement_record_length = sizeof(measurement_record);
    status = spdm_send_receive_get_measurement (spdm_context, &session_id, 0,
                                                measurement_record,
                                                &measurement_record_length);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("spdm_send_receive_get_measurement - %x\n", (uint32_t)status);
        return;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "write file - %s\n", measurement_name));
    libspdm_write_output_file (measurement_name,
                               measurement_record, measurement_record_length);

    /* get cert_chain 1 ~ 7 */
    for (slot_id = 1; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        cert_chain.cert_chain_size = sizeof(cert_chain.cert_chain);
        libspdm_zero_mem (cert_chain.cert_chain, sizeof(cert_chain.cert_chain));
        status = libspdm_get_certificate_ex(
            spdm_context, &session_id, slot_id,
            &cert_chain.cert_chain_size,
            cert_chain.cert_chain,
            NULL, 0);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("libspdm_get_certificate (slot=%d) - %x\n", slot_id, (uint32_t)status);
            cert_chain.cert_chain_size = 0;
        }
        cert_chain_name[18] = slot_id + '0';
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "write file - %s\n", cert_chain_name));
        libspdm_write_output_file (cert_chain_name,
                                   cert_chain.cert_chain,
                                   cert_chain.cert_chain_size);
    }

    /* stop session */
    status = libspdm_stop_session(spdm_context, session_id, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_stop_session - %x\n", (uint32_t)status);
        return;
    }

    return;
}
