/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __MCTP_COMMON_LIB_H__
#define __MCTP_COMMON_LIB_H__

#include "industry_standard/mctp.h"
#include "industry_standard/pldm.h"

/* definition following PLDM specification*/

/* PLDM Header first byte*/
#define PLDM_HEADER_REQUEST_MASK 0x80
#define PLDM_HEADER_DATAGRAM_MASK 0x40
#define PLDM_HEADER_INSTANCE_ID_MASK 0x1F

/* PLDM Header second byte*/
#define PLDM_HEADER_VERSION 0x00
#define PLDM_HEADER_VERSION_MASK 0xC0
#define PLDM_HEADER_TYPE_MASK 0x3F

#pragma pack(1)

/* PLDM GET_TID request*/

typedef struct {
    pldm_message_header_t pldm_header;
} pldm_get_tid_request_t;

/* PLDM GET_TID response*/

typedef struct {
    pldm_message_header_t pldm_header;
    pldm_message_response_header_t pldm_response_header;
    uint8_t tid;
} pldm_get_tid_response_t;

#pragma pack()

/* MCTP app message - check below configuration*/
/* only PLDM*/
#define MCTP_MAX_MESSAGE_SIZE 0x100

/* defintion for library*/
typedef struct {
    uint8_t pldm_type; /* BIT[0:5] type, BIT[6:7] RSVD*/
    uint8_t pldm_command_code;
} pldm_dispatch_type_t;

#endif
