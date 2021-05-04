/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#ifndef __SPDM_TEST_COMMAND_H__
#define __SPDM_TEST_COMMAND_H__

#define DEFAULT_SPDM_PLATFORM_PORT 2323

//
// Client->Server/Server->Client
//   command/response: 4 bytes (big endian)
//   transport_type: 4 bytes (big endian)
//   PayloadSize (excluding command and PayloadSize): 4 bytes (big endian)
//   payload (SPDM message, starting from SPDM_HEADER): PayloadSize (little endian)
//

#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02

#define SOCKET_SPDM_COMMAND_NORMAL 0x0001
#define SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE 0x8001
#define SOCKET_SPDM_COMMAND_CONTINUE 0xFFFD
#define SOCKET_SPDM_COMMAND_SHUTDOWN 0xFFFE
#define SOCKET_SPDM_COMMAND_UNKOWN 0xFFFF
#define SOCKET_SPDM_COMMAND_TEST 0xDEAD

//
// Vendor message
//
#pragma pack(1)

///
/// SPDM VENDOR_DEFINED request
///
typedef struct {
	spdm_message_header_t header;
	// param1 == RSVD
	// param2 == RSVD
	uint16 standard_id;
	uint8 len;
	uint16 vendor_id;
	uint16 payload_length;
	pci_protocol_header_t pci_protocol;
	pci_ide_km_query_t pci_ide_km_query;
} spdm_vendor_defined_request_mine_t;

///
/// SPDM VENDOR_DEFINED response
///
typedef struct {
	spdm_message_header_t header;
	// param1 == RSVD
	// param2 == RSVD
	uint16 standard_id;
	uint8 len;
	uint16 vendor_id;
	uint16 payload_length;
	pci_protocol_header_t pci_protocol;
	pci_ide_km_query_resp_t pci_ide_km_query_resp;
} spdm_vendor_defined_response_mine_t;

///
/// Secure Session APP request
///
typedef struct {
	mctp_message_header_t mctp_header;
	pldm_message_header_t pldm_header;
} secure_session_request_mine_t;

///
/// Secure Session APP response
///
typedef struct {
	mctp_message_header_t mctp_header;
	pldm_message_header_t pldm_header;
	pldm_message_response_header_t pldm_response_header;
	uint8 tid;
} secure_session_response_mine_t;

///
/// DOE Discovery request
///
typedef struct {
	pci_doe_data_object_header_t doe_header;
	pci_doe_discovery_request_t doe_discovery_request;
} doe_discovery_request_mine_t;

///
/// DOE Discovery response
///
typedef struct {
	pci_doe_data_object_header_t doe_header;
	pci_doe_discovery_response_t doe_discovery_response;
} doe_discovery_response_mine_t;

#pragma pack()

#endif