/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

bool InitConnectionAndHandShake(SOCKET *sock, uint16_t port_number) {
    bool result;
    uint8_t handshake_buf[TCP_HANDSHAKE_BUFFER_SIZE];
    tcp_spdm_binding_header_t *tcp_message_header;
    SOCKET responder_socket;

    result = init_client(&responder_socket, port_number);
    if (!result) {
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    /* Create handshake_request */  
    libspdm_zero_mem(handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    tcp_message_header = (tcp_spdm_binding_header_t *) &handshake_buf;
    tcp_message_header->payload_length = TCP_HANDSHAKE_BUFFER_SIZE - 2;
    tcp_message_header->message_type = TCP_MESSAGE_TYPE_HANDSHAKE_REQUEST;

    /* Send handshake_request */
    printf("Press ENTER to send handshake_request...\n");
    getchar();
    result = write_bytes(responder_socket, handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    if (!result) {
        closesocket(responder_socket);
        printf("Error sending handshake request. \n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    *sock = responder_socket;

    return true;
}