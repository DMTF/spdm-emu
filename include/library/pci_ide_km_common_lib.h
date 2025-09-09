/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __PCI_IDE_KM_COMMON_LIB_H__
#define __PCI_IDE_KM_COMMON_LIB_H__

#include "industry_standard/pci_idekm.h"

/*
 * +---------------------------------+
 * | IDE Capability                  |
 * +---------------------------------+
 * | IDE Control                     |
 * +---------------------------------+ ------
 * | Link IDE Stream Control         |       |
 * +---------------------------------+        > PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT
 * | Link IDE Stream Status          |       |
 * +---------------------------------+ ------
 * | Selective IDE Stream Capability |       |
 * +---------------------------------+       |
 * | Selective IDE Stream Control    |       |
 * +---------------------------------+       |
 * | Selective IDE Stream Status     |       |
 * +---------------------------------+       |
 * | IDE RID Association Reg 1       |       |
 * +---------------------------------+        > PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT
 * | IDE RID Association Reg 2       |       |
 * +---------------------------------+ --    |
 * | IDE Address Association Reg 1   |   |   |
 * +---------------------------------+   |   |
 * | IDE Address Association Reg 2   |    > PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT
 * +---------------------------------+   |   |
 * | IDE Address Association Reg 3   |   |   |
 * +---------------------------------+ ------
 */

/* (2 + 2 * 8 + (3 + 2 + 3 * 15) * 255) = 12768 */
#define PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT \
    (2 + \
     2 * PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT + \
     (3 + 2 + 3 * PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT) * \
     PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT)



#define PCI_IDE_KM_LINK_IDE_REG_BLOCK_SUPPORTED_COUNT 4
#define PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_SUPPORTED_COUNT 8
#define PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_SUPPORTED_COUNT 1

/* (2 + 2 * 4 + (3 + 2 + 3 * 1) * 8) = 74 */
#define PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT \
    (2 + \
     2 * PCI_IDE_KM_LINK_IDE_REG_BLOCK_SUPPORTED_COUNT + \
     (3 + 2 + 3 * PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_SUPPORTED_COUNT) * \
     PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_SUPPORTED_COUNT)

typedef struct {
    uint32_t key[8];
    uint32_t iv[2];
} pci_ide_km_aes_256_gcm_key_buffer_t;

#endif
