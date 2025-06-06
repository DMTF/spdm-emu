/**
 *  Copyright Notice:
 *  Copyright 2023 - 2005 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

bool InitConnectionAndRoleInquiry(SOCKET *sock, uint16_t port_number) {
    bool result;
    uint8_t role_inquiry_buf[sizeof(spdm_tcp_binding_header_t)];
    spdm_tcp_binding_header_t *tcp_message_header;
    SOCKET responder_socket;

    result = init_client(&responder_socket, port_number);
    if (!result) {
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    /* Create role_inquiry request */
    libspdm_zero_mem(role_inquiry_buf, sizeof(role_inquiry_buf));
    tcp_message_header = (spdm_tcp_binding_header_t *) &role_inquiry_buf;
    tcp_message_header->payload_length = 0;
    tcp_message_header->binding_version = 1;
    tcp_message_header->message_type = SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY;

    /* Send role_inquiry request */
    printf("Press ENTER to send role_inquiry request...\n");
    getchar();
    result = write_bytes(responder_socket, role_inquiry_buf, sizeof(role_inquiry_buf));
    if (!result) {
        closesocket(responder_socket);
        printf("Error sending role_inquiry request. \n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    *sock = responder_socket;

    return true;
}
