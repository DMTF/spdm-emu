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
    uint8_t slot_mask;
    spdm_attester_cert_chain_struct_t cert_chain[SPDM_MAX_SLOT_COUNT];
    uint8_t slot_id;
    char cert_chain_name[] = "device_cert_chain_0.bin";
    char measurement_name[] = "device_measurement.bin";

    slot_mask = 0;
    libspdm_zero_mem (cert_chain, sizeof(cert_chain));
    status = spdm_authentication (spdm_context, &slot_mask, cert_chain);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "spdm_authentication - fail\n"));
        return ;
    }

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        cert_chain_name[18] = slot_id + '0';
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "write file - %s\n", cert_chain_name));
        libspdm_write_output_file (cert_chain_name,
                                   cert_chain[slot_id].cert_chain,
                                   cert_chain[slot_id].cert_chain_size);
    }

    measurement_record_length = sizeof(measurement_record);
    status = spdm_send_receive_get_measurement (spdm_context, NULL,
                                                measurement_record,
                                                &measurement_record_length);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "spdm_send_receive_get_measurement - fail\n"));
        return ;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "write file - %s\n", measurement_name));
    libspdm_write_output_file (measurement_name,
                               measurement_record, measurement_record_length);

    return ;
}
