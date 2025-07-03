/**
 *  Copyright Notice:
 *  Copyright 2023 - 2005 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

SOCKET CreateSocketAndRoleInquiry(SOCKET *sock, uint16_t port_number) {
    bool result;
    struct sockaddr_in peer_address;
    uint32_t length;
    char buffer[INET_ADDRSTRLEN];
    uint8_t role_inquiry_buf[sizeof(spdm_tcp_binding_header_t)];
    size_t role_inquiry_size = sizeof(role_inquiry_buf);
    SOCKET requester_socket, incoming_socket;

    result = create_socket(port_number, &requester_socket);
    if (!result) {
        printf("Create platform service socket failed\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    printf("Platform server listening on port %d\n", port_number);
    length = sizeof(peer_address);
    incoming_socket = accept(requester_socket, (struct sockaddr *)&peer_address,
                             (socklen_t *)&length);
    if (incoming_socket == INVALID_SOCKET) {
        closesocket(requester_socket);
        printf("Accept error. Error: 0x%x\n",
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

    inet_ntop(AF_INET, &peer_address.sin_addr, buffer, sizeof(buffer));
    printf("Connected to peer at: %s\n", buffer);

    libspdm_zero_mem(role_inquiry_buf, sizeof(role_inquiry_buf));
    result = read_bytes(incoming_socket, role_inquiry_buf, sizeof(role_inquiry_buf));
    if (!result) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Failed to read Role-Inquiry data\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    uint8_t message_type = 0;
    libspdm_return_t status = libspdm_tcp_decode_discovery_message(
        role_inquiry_size, role_inquiry_buf, &message_type
        );

    if (status != LIBSPDM_STATUS_SUCCESS || message_type != SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Invalid or unexpected Role-Inquiry message. Status: 0x%x\n", status);
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    *sock = requester_socket;
    return incoming_socket;
}
