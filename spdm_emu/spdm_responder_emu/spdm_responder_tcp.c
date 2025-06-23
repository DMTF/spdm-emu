/**
 *  Copyright Notice:
 *  Copyright 2023 - 2005 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_emu.h"

bool InitConnectionAndRoleInquiry(SOCKET *sock, uint16_t port_number) {
    bool result;
    uint8_t role_inquiry_buf[sizeof(spdm_tcp_binding_header_t)];
    size_t role_inquiry_size = sizeof(role_inquiry_buf);
    SOCKET responder_socket;

    result = init_client(&responder_socket, port_number);
    if (!result) {
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    void *message_ptr = &role_inquiry_buf;
    libspdm_return_t status = libspdm_tcp_encode_discovery_message(
        SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY,
        &role_inquiry_size,
        &message_ptr
        );

    if (status != LIBSPDM_STATUS_SUCCESS) {
        closesocket(responder_socket);
        printf("Failed to encode Role-Inquiry message. Status: 0x%x\n", status);
        return false;
    }

    /* Send role_inquiry request */
    printf("Press ENTER to send Role-Inquiry request...\n");
    getchar();
    result = write_bytes(responder_socket, role_inquiry_buf, (uint32_t)role_inquiry_size);
    if (!result) {
        closesocket(responder_socket);
        printf("Error sending Role-Inquiry request.\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return false;
    }

    *sock = responder_socket;
    return true;
}
