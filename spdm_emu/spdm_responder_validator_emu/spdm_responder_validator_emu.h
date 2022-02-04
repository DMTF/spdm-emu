/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RESPONDER_VALIDATOR_EMU_H__
#define __SPDM_RESPONDER_VALIDATOR_EMU_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_none_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/mctp_requester_lib.h"
#include "library/pci_doe_requester_lib.h"
#include "library/spdm_responder_conformance_test_lib.h"

#include "os_include.h"
#include "stdio.h"
#include "spdm_emu.h"

extern common_test_suite_config_t m_spdm_responder_validator_config;

#endif
