/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"

uint32_t pci_cfg_read_32 (uint8_t bus, uint8_t device, uint8_t function, uint32_t offset)
{
    size_t address;
    address = SPDM_DEVICE_PCIE_ADDRESS + PCI_ECAM_ADDRESS(bus, device, function, offset);
    return *(uint32_t *)address;
}

void pci_cfg_write_32 (uint8_t bus, uint8_t device, uint8_t function, uint32_t offset,
                       uint32_t value)
{
    size_t address;
    address = SPDM_DEVICE_PCIE_ADDRESS + PCI_ECAM_ADDRESS(bus, device, function, offset);
    *(uint32_t *)address = value;
}

uint32_t spdm_dev_pci_cfg_read_32 (uint32_t offset)
{
    return pci_cfg_read_32 (SPDM_DEVICE_PCI_BUS, SPDM_DEVICE_PCI_DEVICE, SPDM_DEVICE_PCI_FUNCTION,
                            offset);
}

void spdm_dev_pci_cfg_write_32 (uint32_t offset, uint32_t value)
{
    pci_cfg_write_32 (SPDM_DEVICE_PCI_BUS, SPDM_DEVICE_PCI_DEVICE, SPDM_DEVICE_PCI_FUNCTION, offset,
                      value);
}

uint32_t spdm_dev_pci_cfg_doe_read_32 (uint32_t doe_offset)
{
    return spdm_dev_pci_cfg_read_32 (SPDM_DEVICE_DOE_OFFSET + doe_offset);
}

void spdm_dev_pci_cfg_doe_write_32 (uint32_t doe_offset, uint32_t value)
{
    spdm_dev_pci_cfg_write_32 (SPDM_DEVICE_DOE_OFFSET + doe_offset, value);
}
