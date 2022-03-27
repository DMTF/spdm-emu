/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

uint32_t m_command;

SOCKET m_server_socket;

extern void *m_spdm_context;
extern void *m_scratch_buffer;
extern void *m_pci_doe_context;

void *spdm_server_init(void);

bool create_socket(uint16_t port_number, SOCKET *listen_socket)
{
    struct sockaddr_in my_address;
    int32_t res;

    /* Initialize Winsock*/
#ifdef _MSC_VER
    WSADATA ws;
    res = WSAStartup(MAKEWORD(2, 2), &ws);
    if (res != 0) {
        printf("WSAStartup failed with error: %d\n", res);
        return false;
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
        return false;
    }

    /* When the program stops unexpectedly the used port will stay in the TIME_WAIT
     * state which prevents other programs from binding to this port until a timeout
     * triggers. This timeout may be 30s to 120s. In this state the responder cannot
     * be restarted since it cannot bind to its port.
     * To prevent this SO_REUSEADDR is applied to the socket which allows the
     * responder to bind to this port even if it is still in the TIME_WAIT state.*/
    if (setsockopt(*listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        printf("Cannot configure server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return false;
    }

    libspdm_zero_mem(&my_address, sizeof(my_address));
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
        return false;
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
        return false;
    }
    return true;
}

bool platform_server(const SOCKET socket)
{
    bool result;
    libspdm_return_t status;
    uint8_t response[PCI_DOE_MAX_NON_SPDM_MESSAGE_SIZE];
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
    SOCKET listen_socket;
    struct sockaddr_in peer_address;
    bool result;
    uint32_t length;
    bool continue_serving;

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
            return false;
        }
        printf("Client accepted\n");

        continue_serving = platform_server(m_server_socket);
        closesocket(m_server_socket);

    } while (continue_serving);
#ifdef _MSC_VER
    WSACleanup();
#endif
    closesocket(listen_socket);
    return true;
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
