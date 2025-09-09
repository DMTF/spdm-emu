/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __CXL_IDE_KM_COMMON_LIB_H__
#define __CXL_IDE_KM_COMMON_LIB_H__

#include "industry_standard/cxl_idekm.h"

/*
 * +--------------------------------------+
 * | CXL IDE Capability                   |
 * +--------------------------------------+
 * | CXL_IDE Control                      |
 * +--------------------------------------+
 * | CXL_IDE Status                       |
 * +--------------------------------------+
 * | CXL_IDE Error Status                 |
 * +--------------------------------------+
 * | Key Refresh Time Capability          |
 * +--------------------------------------+
 * | Truncation Transmit Delay Capability |
 * +--------------------------------------+
 * | Key Refresh Time Control             |
 * +--------------------------------------+
 * | Truncation Transmit Delay Control    |
 * +--------------------------------------+
 * | Key Refresh Time Capability2         |
 * +--------------------------------------+
 */

#define CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT 9

typedef struct {
    uint32_t key[8];
    uint32_t iv[3];
} cxl_ide_km_aes_256_gcm_key_buffer_t;

#endif
