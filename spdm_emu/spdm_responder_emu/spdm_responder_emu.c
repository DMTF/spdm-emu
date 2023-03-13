/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

uint32_t m_command;

SOCKET m_server_socket;

extern void *m_spdm_context;
extern void *m_scratch_buffer;
extern void *m_pci_doe_context;

void *spdm_server_init(void);
libspdm_return_t pci_doe_init_responder ();

bool InitConnectionAndHandShake(SOCKET *sock, uint16_t port_number);

bool platform_server(const SOCKET socket)
{
    bool result;
    libspdm_return_t status;
    uint8_t response[LIBPCIDOE_MAX_NON_SPDM_MESSAGE_SIZE];
    size_t response_size;

    while (true) {
        status = libspdm_responder_dispatch_message(m_spdm_context);
        if (status == LIBSPDM_STATUS_SUCCESS) {
            /* success dispatch SPDM message*/
        }
        if ((status == LIBSPDM_STATUS_SEND_FAIL) ||
            (status == LIBSPDM_STATUS_RECEIVE_FAIL)) {
            printf("Server Critical Error - STOP\n");
            return false;
        }
        if (status != LIBSPDM_STATUS_UNSUPPORTED_CAP) {
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
                return true;
            }
            break;

        case SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE:
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
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
                return true;
            }
#endif
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
                return true;
            }
            return false;
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
                return true;
            }
            return true;
            break;

        case SOCKET_SPDM_COMMAND_NORMAL:
            if (m_use_transport_layer ==
                SOCKET_TRANSPORT_TYPE_PCI_DOE) {
                response_size = sizeof(response);
                status = pci_doe_get_response_doe_request (m_pci_doe_context,
                                                           m_send_receive_buffer,
                                                           m_send_receive_buffer_size, response,
                                                           &response_size);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    /* unknown message*/
                    return true;
                }
                result = send_platform_data(
                    socket, SOCKET_SPDM_COMMAND_NORMAL,
                    response, response_size);
                if (!result) {
                    printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
                           WSAGetLastError()
#else
                           errno
#endif
                           );
                    return true;
                }
            } else {
                /* unknown message*/
                return true;
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
                return true;
            }
            return true;
        }
    }
}

bool platform_server_routine(uint16_t port_number)
{
    SOCKET responder_socket;
    struct sockaddr_in peer_address;
    bool result;
    uint32_t length;
    bool continue_serving;

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
        m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
        result = InitConnectionAndHandShake(&responder_socket, port_number);
        if (!result) {
            return false;
        }
        m_server_socket = responder_socket;
    }
    else {
        result = create_socket(port_number, &responder_socket);
        if (!result) {
            printf("Create platform service socket fail\n");
#ifdef _MSC_VER
            WSACleanup();
#endif
            return false;
        }
    }

    do {
        if (!(m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
              m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE)) {
            printf("Platform server listening on port %d\n", port_number);

            length = sizeof(peer_address);
            m_server_socket =
                accept(responder_socket, (struct sockaddr *)&peer_address,
                       (socklen_t *)&length);
            if (m_server_socket == INVALID_SOCKET) {
                closesocket(responder_socket);
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
                return false;
            }
        }
        continue_serving = platform_server(m_server_socket);
        closesocket(m_server_socket);

    } while (continue_serving);

    closesocket(responder_socket);
#ifdef _MSC_VER
    WSACleanup();
#endif
    return true;
}

int main(int argc, char *argv[])
{
    libspdm_return_t status;

    printf("%s version 0.1\n", "spdm_responder_emu");
    srand((unsigned int)time(NULL));

    process_args("spdm_responder_emu", argc, argv);

    m_spdm_context = spdm_server_init();
    if (m_spdm_context == NULL) {
        return 0;
    }

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        status = pci_doe_init_responder ();
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("pci_doe_init_responder - %x\n", (uint32_t)status);
            return 0;
        }
    }

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP) {
        /* The IANA has assigned port number 4194 for SPDM */
        platform_server_routine(TCP_SPDM_PLATFORM_PORT);
    }
    else {
        platform_server_routine(DEFAULT_SPDM_PLATFORM_PORT);
    }

    if (m_spdm_context != NULL) {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
        free(m_scratch_buffer);
    }

    printf("Server stopped\n");

    close_pcap_packet_file();
    return 0;
}
