/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef PCI_TDISP_DEVICE_INTERFACE_REPORT_JSON_H
#define PCI_TDISP_DEVICE_INTERFACE_REPORT_JSON_H

#include "hal/base.h"

/**
 *  Load a TDISP DEVICE_INTERFACE_REPORT from a JSON file and serialize it into
 *  the supplied byte buffer.
 *
 *  The file is taken from the path specified in TDISP_DEVICE_INTERFACE_REPORT
 *  environment variable when set, otherwise from a built-in default path. The
 *  number of MMIO ranges is inferred from the size of the "mmio_ranges" array
 *  found in the file.
 *
 *  @param buffer        destination buffer (interface_report).
 *  @param buffer_size   size in bytes of buffer.
 *  @param report_size   on success, receives the serialized report size.
 *
 *  @retval true   the report was loaded and serialized into buffer.
 *  @retval false  the file is missing, malformed, or too large for buffer.
 **/
bool pci_tdisp_device_interface_report_load_from_json (uint8_t *buffer,
                                                       size_t buffer_size,
                                                       uint16_t *report_size);

#endif /* PCI_TDISP_DEVICE_INTERFACE_REPORT_JSON_H */
