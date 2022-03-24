/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __MCTP_COMMON_LIB_H__
#define __MCTP_COMMON_LIB_H__

#include "industry_standard/mctp.h"
#include "industry_standard/pldm.h"


/* MCTP app message - check below configuration
 * only PLDM*/
#define MCTP_MAX_MESSAGE_SIZE 0x100

/* defintion for library*/
typedef struct {
    uint8_t pldm_type; /* BIT[0:5] type, BIT[6:7] RSVD*/
    uint8_t pldm_command_code;
} pldm_dispatch_type_t;

#endif
