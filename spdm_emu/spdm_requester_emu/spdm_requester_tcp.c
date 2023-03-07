/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number) {
    bool result;
    struct sockaddr_in peer_address;
    uint32_t length;
    char buffer[INET_ADDRSTRLEN];
    uint8_t handshake_buf[TCP_HANDSHAKE_BUFFER_SIZE];
    tcp_spdm_binding_header_t *tcp_message_header;
    SOCKET requester_socket, incoming_socket;

    result = create_socket(port_number, &requester_socket);
    if (!result) {
        printf("Create platform service socket fail\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    printf("Platform server listening on port %d\n", port_number);
    length = sizeof(peer_address);
    incoming_socket = accept(requester_socket, (struct sockaddr *)&peer_address, (socklen_t *)&length);
    if (incoming_socket == INVALID_SOCKET) {
        closesocket(requester_socket);
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
        return INVALID_SOCKET;
    }

    inet_ntop( AF_INET, &peer_address.sin_addr, buffer, sizeof( buffer ));
    printf("Connected to peer at: %s\n", buffer);

    libspdm_zero_mem(handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    result = read_bytes(incoming_socket, handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    if(!result) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Failed reading handshake data\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    tcp_message_header = (tcp_spdm_binding_header_t *) &handshake_buf;
    if(tcp_message_header->message_type != TCP_MESSAGE_TYPE_HANDSHAKE_REQUEST || tcp_message_header->payload_length != TCP_HANDSHAKE_BUFFER_SIZE - 2) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Failed validating handshake data\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }
 
    *sock = requester_socket;
    return incoming_socket;
}