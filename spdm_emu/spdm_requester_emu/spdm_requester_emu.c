/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

#define IP_ADDRESS "127.0.0.1"

#ifdef _MSC_VER
struct in_addr m_ip_address = { { { 127, 0, 0, 1 } } };
#else
struct in_addr m_ip_address = { 0x0100007F };
#endif
uint8_t m_receive_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern SOCKET m_socket;

extern void *m_spdm_context;

void *spdm_client_init(void);

boolean communicate_platform_data(IN SOCKET socket, IN uint32_t command,
				  IN uint8_t *send_buffer, IN uintn bytes_to_send,
				  OUT uint32_t *response,
				  IN OUT uintn *bytes_to_receive,
				  OUT uint8_t *receive_buffer);

return_status do_measurement_via_spdm(IN uint32_t *session_id);

return_status do_authentication_via_spdm(void);

return_status do_session_via_spdm(IN boolean use_psk);

boolean init_client(OUT SOCKET *sock, IN uint16_t port)
{
	SOCKET client_socket;
	struct sockaddr_in server_addr;
	int32_t ret_val;

	client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_socket == INVALID_SOCKET) {
		printf("Create socket Failed - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return FALSE;
	}

	server_addr.sin_family = AF_INET;
	copy_mem(&server_addr.sin_addr.s_addr, &m_ip_address,
		 sizeof(struct in_addr));
	server_addr.sin_port = htons(port);
	zero_mem(server_addr.sin_zero, sizeof(server_addr.sin_zero));

	ret_val = connect(client_socket, (struct sockaddr *)&server_addr,
			  sizeof(server_addr));
	if (ret_val == SOCKET_ERROR) {
		printf("Connect Error - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		closesocket(client_socket);
		return FALSE;
	}

	printf("connect success!\n");

	*sock = client_socket;
	return TRUE;
}

doe_discovery_request_mine_t m_doe_request = {
	{
		PCI_DOE_VENDOR_ID_PCISIG,
		PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, 0,
		sizeof(m_doe_request) / sizeof(uint32_t), // length
	},
	{
		0, // index
	},
};

boolean platform_client_routine(IN uint16_t port_number)
{
	SOCKET platform_socket;
	boolean result;
	uint32_t response;
	uintn response_size;
	return_status status;

#ifdef _MSC_VER
	WSADATA ws;
	if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
		printf("Init Windows socket Failed - %x\n", WSAGetLastError());
		return FALSE;
	}
#endif
	result = init_client(&platform_socket, port_number);
	if (!result) {
		return FALSE;
	}

	m_socket = platform_socket;

	if (m_use_transport_layer != SOCKET_TRANSPORT_TYPE_NONE) {
		response_size = sizeof(m_receive_buffer);
		result = communicate_platform_data(
			platform_socket,
			SOCKET_SPDM_COMMAND_TEST,
			(uint8_t *)"Client Hello!",
			sizeof("Client Hello!"), &response,
			&response_size, m_receive_buffer);
		if (!result) {
			goto done;
		}
	}

	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
		doe_discovery_response_mine_t doe_response;

		do {
			response_size = sizeof(doe_response);
			result = communicate_platform_data(
				platform_socket, SOCKET_SPDM_COMMAND_NORMAL,
				(uint8_t *)&m_doe_request, sizeof(m_doe_request),
				&response, &response_size,
				(uint8_t *)&doe_response);
			if (!result) {
				goto done;
			}
			ASSERT(response_size == sizeof(doe_response));
			ASSERT(doe_response.doe_header.vendor_id ==
			       PCI_DOE_VENDOR_ID_PCISIG);
			ASSERT(doe_response.doe_header.data_object_type ==
			       PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY);
			ASSERT(doe_response.doe_header.length ==
			       sizeof(doe_response) / sizeof(uint32_t));
			ASSERT(doe_response.doe_discovery_response.vendor_id ==
			       PCI_DOE_VENDOR_ID_PCISIG);

			m_doe_request.doe_discovery_request.index =
				doe_response.doe_discovery_response.next_index;
		} while (doe_response.doe_discovery_response.next_index != 0);
	}

	m_spdm_context = spdm_client_init();
	if (m_spdm_context == NULL) {
		goto done;
	}

	// Do test - begin

	status = do_authentication_via_spdm();
	if (RETURN_ERROR(status)) {
		printf("do_authentication_via_spdm - %x\n", (uint32_t)status);
		goto done;
	}

	if ((m_exe_connection & EXE_CONNECTION_MEAS) != 0) {
		status = do_measurement_via_spdm(NULL);
		if (RETURN_ERROR(status)) {
			printf("do_measurement_via_spdm - %x\n",
			       (uint32_t)status);
			goto done;
		}
	}

	if (m_use_version >= SPDM_MESSAGE_VERSION_11) {
		if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
			status = do_session_via_spdm(FALSE);
			if (RETURN_ERROR(status)) {
				printf("do_session_via_spdm - %x\n",
				       (uint32_t)status);
				goto done;
			}
		}

		if ((m_exe_session & EXE_SESSION_PSK) != 0) {
			status = do_session_via_spdm(TRUE);
			if (RETURN_ERROR(status)) {
				printf("do_session_via_spdm - %x\n",
				       (uint32_t)status);
				goto done;
			}
		}
	}

	// Do test - end

done:
	response_size = 0;
	result = communicate_platform_data(
		platform_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
		NULL, 0, &response, &response_size, NULL);

	if (m_spdm_context != NULL) {
		free(m_spdm_context);
	}

	closesocket(platform_socket);

#ifdef _MSC_VER
	WSACleanup();
#endif

	return TRUE;
}

int main(int argc, char *argv[])
{
	printf("%s version 0.1\n", "spdm_requester_emu");
	srand((unsigned int)time(NULL));

	process_args("spdm_requester_emu", argc, argv);

	platform_client_routine(DEFAULT_SPDM_PLATFORM_PORT);
	printf("Client stopped\n");

	close_pcap_packet_file();
	return 0;
}
