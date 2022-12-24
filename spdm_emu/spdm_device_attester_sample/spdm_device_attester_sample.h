/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_DEVICE_ATTESTER_SAMPLE_H__
#define __SPDM_DEVICE_ATTESTER_SAMPLE_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_none_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/mctp_requester_lib.h"
#include "library/pci_doe_requester_lib.h"

#include "os_include.h"
#include "stdio.h"
#include "spdm_emu.h"

typedef struct {
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
} spdm_attester_cert_chain_struct_t;

libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id,
                                                   uint8_t slot_id,
                                                   uint8_t *measurement_record,
                                                   uint32_t *measurement_record_length);

void spdm_device_evidence_collection (void *spdm_context);

#endif
