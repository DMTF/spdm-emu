/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_TEST_COMMAND_H__
#define __SPDM_TEST_COMMAND_H__

#define DEFAULT_SPDM_PLATFORM_PORT 2323


/* Client->Server/Server->Client
 *   command/response: 4 bytes (big endian)
 *   transport_type: 4 bytes (big endian)
 *   PayloadSize (excluding command and PayloadSize): 4 bytes (big endian)
 *   payload (SPDM message, starting from SPDM_HEADER): PayloadSize (little endian)*/


#define SOCKET_TRANSPORT_TYPE_NONE 0x00
#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02

#define SOCKET_SPDM_COMMAND_NORMAL 0x0001
#define SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE 0x8001
#define SOCKET_SPDM_COMMAND_CONTINUE 0xFFFD
#define SOCKET_SPDM_COMMAND_SHUTDOWN 0xFFFE
#define SOCKET_SPDM_COMMAND_UNKOWN 0xFFFF
#define SOCKET_SPDM_COMMAND_TEST 0xDEAD

#endif
