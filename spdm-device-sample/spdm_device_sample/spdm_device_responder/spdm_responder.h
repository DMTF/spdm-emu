/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RESPONDER_H__
#define __SPDM_RESPONDER_H__

#include "hal/base.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/malloclib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE    LIBSPDM_PCI_DOE_TRANSPORT_ADDITIONAL_SIZE

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                        LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY 0
#endif

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_SENDER_RECEIVER_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                         LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                               LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_LAST_SPDM_REQUEST_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
#define LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_SIZE (LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_SENDER_RECEIVER_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LAST_SPDM_REQUEST_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY)

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

#define SPDM_DEVICE_PCI_BUS       0 /* TBD */
#define SPDM_DEVICE_PCI_DEVICE    0 /* TBD */
#define SPDM_DEVICE_PCI_FUNCTION  0 /* TBD */

#define SPDM_DEVICE_PCIE_ADDRESS  0xE0000000 /* TBD */

#define SPDM_DEVICE_DOE_OFFSET    0x880 /* TBD */

/* standard - begin */

/*
 * The Data Object Exchange PCI Express Extended Capability definitions.
 * Based on section x.x.x of PCI Express Base Specification x.x.
 *  */
#define PCI_EXPRESS_EXTENDED_CAPABILITY_DOE_ID   0x002E
#define PCI_EXPRESS_EXTENDED_CAPABILITY_DOE_VER1 0x1

/*
 * Register offsets from Data Object Exchange PCIe Ext Cap Header
 *  */
#define PCI_EXPRESS_REG_DOE_CAPABILITIES_OFFSET             0x04
#define PCI_EXPRESS_REG_DOE_CONTROL_OFFSET                  0x08
#define PCI_EXPRESS_REG_DOE_STATUS_OFFSET                   0x0C
#define PCI_EXPRESS_REG_DOE_WRITE_DATA_MAILBOX_OFFSET       0x10
#define PCI_EXPRESS_REG_DOE_READ_DATA_MAILBOX_OFFSET        0x14

#pragma pack(1)

#define PCI_EXPRESS_REG_DOE_CAPABILITIES_BIT_INTERRUPT_SUPPORT 0x1

#define PCI_EXPRESS_REG_DOE_CONTROL_BIT_ABORT            0x1
#define PCI_EXPRESS_REG_DOE_CONTROL_BIT_INTERRUPT_ENABLE 0x2
#define PCI_EXPRESS_REG_DOE_CONTROL_BIT_GO               0x80000000

#define PCI_EXPRESS_REG_DOE_STATUS_BIT_BUSY              0x1
#define PCI_EXPRESS_REG_DOE_STATUS_BIT_INTERRUPT         0x2
#define PCI_EXPRESS_REG_DOE_STATUS_BIT_ERROR             0x4
#define PCI_EXPRESS_REG_DOE_STATUS_BIT_DATA_READY        0x80000000

typedef struct {
    uint32_t header;
    uint32_t capability;
    uint32_t control;
    uint32_t status;
    uint32_t write_data_mailbox;
    uint32_t read_data_mailbox;
} pci_express_doe_struct_t;

#pragma pack()

#define PCI_ECAM_ADDRESS(bus, device, function, offset) \
    (((offset) & 0xfff) | (((function) & 0x07) << 12) | (((device) & 0x1f) << 15) | \
     (((bus) & 0xff) << 20))

/* standard - end */

void *spdm_server_init(void);

libspdm_return_t pci_doe_init_responder();

libspdm_return_t spdm_get_response_vendor_defined_request(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response);

uint32_t spdm_dev_pci_cfg_doe_read_32 (uint32_t doe_offset);

void spdm_dev_pci_cfg_doe_write_32 (uint32_t doe_offset, uint32_t value);

#endif
