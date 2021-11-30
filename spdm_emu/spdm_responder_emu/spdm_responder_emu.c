/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_emu.h"

uint32_t m_command;
uintn m_receive_buffer_size;
uint8_t m_receive_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

SOCKET m_server_socket;

extern void *m_spdm_context;

void *spdm_server_init(void);

boolean create_socket(IN uint16_t port_number, IN SOCKET *listen_socket)
{
	struct sockaddr_in my_address;
	int32_t res;

	// Initialize Winsock
#ifdef _MSC_VER
	WSADATA ws;
	res = WSAStartup(MAKEWORD(2, 2), &ws);
	if (res != 0) {
		printf("WSAStartup failed with error: %d\n", res);
		return FALSE;
	}
#endif

	*listen_socket = socket(PF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == *listen_socket) {
		printf("Cannot create server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return FALSE;
	}

        // When the program stops unexpectedly the used port will stay in the TIME_WAIT
        // state which prevents other programs from binding to this port until a timeout
        // triggers. This timeout may be 30s to 120s. In this state the responder cannot
        // be restarted since it cannot bind to its port.
        // To prevent this SO_REUSEADDR is applied to the socket which allows the
        // responder to bind to this port even if it is still in the TIME_WAIT state.
	if (setsockopt(*listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		printf("Cannot configure server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return FALSE;
	}

	zero_mem(&my_address, sizeof(my_address));
	my_address.sin_port = htons((short)port_number);
	my_address.sin_family = AF_INET;

	res = bind(*listen_socket, (struct sockaddr *)&my_address,
		   sizeof(my_address));
	if (res == SOCKET_ERROR) {
		printf("Bind error.  Error is 0x%x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		closesocket(*listen_socket);
		return FALSE;
	}

	res = listen(*listen_socket, 3);
	if (res == SOCKET_ERROR) {
		printf("Listen error.  Error is 0x%x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		closesocket(*listen_socket);
		return FALSE;
	}
	return TRUE;
}

doe_discovery_response_mine_t m_doe_response = {
	{
		PCI_DOE_VENDOR_ID_PCISIG,
		PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, 0,
		sizeof(m_doe_response) / sizeof(uint32_t), // length
	},
	{ PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
	  0x00 },
};

boolean platform_server(IN SOCKET socket)
{
	boolean result;
	return_status status;

	while (TRUE) {
		status = libspdm_responder_dispatch_message(m_spdm_context);
		if (status == RETURN_SUCCESS) {
			// success dispatch SPDM message
		}
		if (status == RETURN_DEVICE_ERROR) {
			printf("Server Critical Error - STOP\n");
			return FALSE;
		}
		if (status != RETURN_UNSUPPORTED) {
			continue;
		}
		switch (m_command) {
		case SOCKET_SPDM_COMMAND_TEST:
			result = send_platform_data(socket,
						    SOCKET_SPDM_COMMAND_TEST,
						    (uint8_t *)"Server Hello!",
						    sizeof("Server Hello!"));
			if (!result) {
				printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
				       WSAGetLastError()
#else
				       errno
#endif
				);
				return TRUE;
			}
			break;

		case SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE:
			libspdm_init_key_update_encap_state(m_spdm_context);
			result = send_platform_data(
				socket,
				SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL,
				0);
			if (!result) {
				printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
				       WSAGetLastError()
#else
				       errno
#endif
				);
				return TRUE;
			}
			break;

		case SOCKET_SPDM_COMMAND_SHUTDOWN:
			result = send_platform_data(
				socket, SOCKET_SPDM_COMMAND_SHUTDOWN, NULL, 0);
			if (!result) {
				printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
				       WSAGetLastError()
#else
				       errno
#endif
				);
				return TRUE;
			}
			return FALSE;
			break;

		case SOCKET_SPDM_COMMAND_CONTINUE:
			result = send_platform_data(
				socket, SOCKET_SPDM_COMMAND_CONTINUE, NULL, 0);
			if (!result) {
				printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
				       WSAGetLastError()
#else
				       errno
#endif
				);
				return TRUE;
			}
			return TRUE;
			break;

		case SOCKET_SPDM_COMMAND_NORMAL:
			if (m_use_transport_layer ==
			    SOCKET_TRANSPORT_TYPE_PCI_DOE) {
				doe_discovery_request_mine_t *doe_request;

				doe_request = (void *)m_receive_buffer;
				if ((doe_request->doe_header.vendor_id !=
				     PCI_DOE_VENDOR_ID_PCISIG) ||
				    (doe_request->doe_header.data_object_type !=
				     PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY)) {
					// unknown message
					return TRUE;
				}
				ASSERT(m_receive_buffer_size ==
				       sizeof(doe_discovery_request_mine_t));
				ASSERT(doe_request->doe_header.length ==
				       sizeof(*doe_request) / sizeof(uint32_t));

				switch (doe_request->doe_discovery_request
						.index) {
				case 0:
					m_doe_response.doe_discovery_response
						.data_object_type =
						PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
					m_doe_response.doe_discovery_response
						.next_index = 1;
					break;
				case 1:
					m_doe_response.doe_discovery_response
						.data_object_type =
						PCI_DOE_DATA_OBJECT_TYPE_SPDM;
					m_doe_response.doe_discovery_response
						.next_index = 2;
					break;
				case 2:
				default:
					m_doe_response.doe_discovery_response
						.data_object_type =
						PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
					m_doe_response.doe_discovery_response
						.next_index = 0;
					break;
				}

				result = send_platform_data(
					socket, SOCKET_SPDM_COMMAND_NORMAL,
					(uint8_t *)&m_doe_response,
					sizeof(m_doe_response));
				if (!result) {
					printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
					       WSAGetLastError()
#else
					       errno
#endif
					);
					return TRUE;
				}
			} else {
				// unknown message
				return TRUE;
			}
			break;

		default:
			printf("Unrecognized platform interface command %x\n",
			       m_command);
			result = send_platform_data(
				socket, SOCKET_SPDM_COMMAND_UNKOWN, NULL, 0);
			if (!result) {
				printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
				       WSAGetLastError()
#else
				       errno
#endif
				);
				return TRUE;
			}
			return TRUE;
		}
	}
}

boolean platform_server_routine(IN uint16_t port_number)
{
	SOCKET listen_socket;
	struct sockaddr_in peer_address;
	boolean result;
	uint32_t length;
	boolean continue_serving;

	result = create_socket(port_number, &listen_socket);
	if (!result) {
		printf("Create platform service socket fail\n");
		return result;
	}

	do {
		printf("Platform server listening on port %d\n", port_number);

		length = sizeof(peer_address);
		m_server_socket =
			accept(listen_socket, (struct sockaddr *)&peer_address,
			       (socklen_t *)&length);
		if (m_server_socket == INVALID_SOCKET) {
			printf("Accept error.  Error is 0x%x\n",
#ifdef _MSC_VER
			       WSAGetLastError()
#else
			       errno
#endif
			);
#ifdef _MSC_VER
			WSACleanup();
#endif
			closesocket(listen_socket);
			return FALSE;
		}
		printf("Client accepted\n");

		continue_serving = platform_server(m_server_socket);
		closesocket(m_server_socket);

	} while (continue_serving);
#ifdef _MSC_VER
	WSACleanup();
#endif
	closesocket(listen_socket);
	return TRUE;
}

int main(int argc, char *argv[])
{
	printf("%s version 0.1\n", "spdm_responder_emu");
	srand((unsigned int)time(NULL));

	process_args("spdm_responder_emu", argc, argv);

	m_spdm_context = spdm_server_init();
	if (m_spdm_context == NULL) {
		return 0;
	}

	platform_server_routine(DEFAULT_SPDM_PLATFORM_PORT);

	free(m_spdm_context);

	printf("Server stopped\n");

	close_pcap_packet_file();
	return 0;
}
