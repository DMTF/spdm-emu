/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_emu.h"

/* hack to add MCTP header for PCAP*/
#include "industry_standard/mctp.h"

uint32_t m_use_transport_layer = SOCKET_TRANSPORT_TYPE_MCTP;

bool m_send_receive_buffer_acquired = false;
uint8_t m_send_receive_buffer[LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE];
size_t m_send_receive_buffer_size;

/**
 * Read number of bytes data in blocking mode.
 *
 * If there is no enough data in socket, this function will wait.
 * This function will return if enough data is read, or socket error.
 **/
bool read_bytes(const SOCKET socket, uint8_t *buffer,
                uint32_t number_of_bytes)
{
    int32_t result;
    uint32_t number_received;

    number_received = 0;
    while (number_received < number_of_bytes) {
        result = recv(socket, (char *)(buffer + number_received),
                      number_of_bytes - number_received, 0);
        if (result == -1) {
            printf("Receive error - 0x%x\n",
#ifdef _MSC_VER
                   WSAGetLastError()
#else
                   errno
#endif
                   );
            return false;
        }
        if (result == 0) {
            return false;
        }
        number_received += result;
    }
    return true;
}

bool read_data32(const SOCKET socket, uint32_t *data)
{
    bool result;

    result = read_bytes(socket, (uint8_t *)data, sizeof(uint32_t));
    if (!result) {
        return result;
    }
    *data = ntohl(*data);
    return true;
}

/**
 * Read multiple bytes in blocking mode.
 *
 * The length is presented as first 4 bytes in big endian.
 * The data follows the length.
 *
 * If there is no enough data in socket, this function will wait.
 * This function will return if enough data is read, or socket error.
 **/
bool read_multiple_bytes(const SOCKET socket, uint8_t *buffer,
                         uint32_t *bytes_received,
                         uint32_t max_buffer_length)
{
    uint32_t length;
    bool result;

    result = read_data32(socket, &length);
    if (!result) {
        return result;
    }
    printf("Platform port Receive size: ");
    length = ntohl(length);
    dump_data((uint8_t *)&length, sizeof(uint32_t));
    printf("\n");
    length = ntohl(length);

    *bytes_received = length;
    if (*bytes_received > max_buffer_length) {
        printf("buffer too small (0x%x). Expected - 0x%x\n",
               max_buffer_length, *bytes_received);
        return false;
    }
    if (length == 0) {
        return true;
    }
    result = read_bytes(socket, buffer, length);
    if (!result) {
        return result;
    }
    printf("Platform port Receive buffer:\n    ");
    dump_data(buffer, length);
    printf("\n");

    return true;
}

bool receive_platform_data(const SOCKET socket, uint32_t *command,
                           uint8_t *receive_buffer,
                           size_t *bytes_to_receive)
{
    bool result;
    uint32_t response;
    uint32_t transport_type;
    uint32_t bytes_received;

    result = read_data32(socket, &response);
    if (!result) {
        return result;
    }
    *command = response;
    printf("Platform port Receive command: ");
    response = ntohl(response);
    dump_data((uint8_t *)&response, sizeof(uint32_t));
    printf("\n");

    result = read_data32(socket, &transport_type);
    if (!result) {
        return result;
    }
    printf("Platform port Receive transport_type: ");
    transport_type = ntohl(transport_type);
    dump_data((uint8_t *)&transport_type, sizeof(uint32_t));
    printf("\n");
    transport_type = ntohl(transport_type);
    if (transport_type != m_use_transport_layer) {
        printf("transport_type mismatch\n");
        return false;
    }

    bytes_received = 0;
    result = read_multiple_bytes(socket, receive_buffer, &bytes_received,
                                 (uint32_t)*bytes_to_receive);
    if (!result) {
        return result;
    }
    *bytes_to_receive = bytes_received;

    switch (*command) {
    case SOCKET_SPDM_COMMAND_SHUTDOWN:
        close_pcap_packet_file();
        break;
    case SOCKET_SPDM_COMMAND_NORMAL:
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {

            /* Append mctp_header_t for PCAP*/

            mctp_header_t mctp_header;
            mctp_header.header_version = 0;
            mctp_header.destination_id = 0;
            mctp_header.source_id = 0;
            mctp_header.message_tag = 0xC0;
            append_pcap_packet_data(&mctp_header,
                                    sizeof(mctp_header),
                                    receive_buffer, bytes_received);
        } else {
            append_pcap_packet_data(NULL, 0, receive_buffer,
                                    bytes_received);
        }
        break;
    }

    return result;
}

/**
 * Write number of bytes data in blocking mode.
 *
 * This function will return if data is written, or socket error.
 **/
bool write_bytes(const SOCKET socket, const uint8_t *buffer,
                 uint32_t number_of_bytes)
{
    int32_t result;
    uint32_t number_sent;

    number_sent = 0;
    while (number_sent < number_of_bytes) {
        result = send(socket, (char *)(buffer + number_sent),
                      number_of_bytes - number_sent, 0);
        if (result == -1) {
#ifdef _MSC_VER
            if (WSAGetLastError() == 0x2745) {
                printf("Client disconnected\n");
            } else {
#endif
            printf("Send error - 0x%x\n",
#ifdef _MSC_VER
                   WSAGetLastError()
#else
                   errno
#endif
                   );
#ifdef _MSC_VER
        }
#endif
            return false;
        }
        number_sent += result;
    }
    return true;
}

bool write_data32(const SOCKET socket, uint32_t data)
{
    data = htonl(data);
    return write_bytes(socket, (uint8_t *)&data, sizeof(uint32_t));
}

/**
 * Write multiple bytes.
 *
 * The length is presented as first 4 bytes in big endian.
 * The data follows the length.
 **/
bool write_multiple_bytes(const SOCKET socket, const uint8_t *buffer,
                          uint32_t bytes_to_send)
{
    bool result;

    result = write_data32(socket, bytes_to_send);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit size: ");
    bytes_to_send = htonl(bytes_to_send);
    dump_data((uint8_t *)&bytes_to_send, sizeof(uint32_t));
    printf("\n");
    bytes_to_send = htonl(bytes_to_send);

    result = write_bytes(socket, buffer, bytes_to_send);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit buffer:\n    ");
    dump_data(buffer, bytes_to_send);
    printf("\n");
    return true;
}

bool send_platform_data(const SOCKET socket, uint32_t command,
                        const uint8_t *send_buffer, size_t bytes_to_send)
{
    bool result;
    uint32_t request;
    uint32_t transport_type;

    request = command;
    result = write_data32(socket, request);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit command: ");
    request = htonl(request);
    dump_data((uint8_t *)&request, sizeof(uint32_t));
    printf("\n");

    result = write_data32(socket, m_use_transport_layer);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit transport_type: ");
    transport_type = ntohl(m_use_transport_layer);
    dump_data((uint8_t *)&transport_type, sizeof(uint32_t));
    printf("\n");

    result = write_multiple_bytes(socket, send_buffer,
                                  (uint32_t)bytes_to_send);
    if (!result) {
        return result;
    }

    switch (command) {
    case SOCKET_SPDM_COMMAND_SHUTDOWN:
        close_pcap_packet_file();
        break;
    case SOCKET_SPDM_COMMAND_NORMAL:
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {

            /* Append mctp_header_t for PCAP*/

            mctp_header_t mctp_header;
            mctp_header.header_version = 0;
            mctp_header.destination_id = 0;
            mctp_header.source_id = 0;
            mctp_header.message_tag = 0xC0;
            append_pcap_packet_data(&mctp_header,
                                    sizeof(mctp_header),
                                    send_buffer, bytes_to_send);
        } else {
            append_pcap_packet_data(NULL, 0, send_buffer,
                                    bytes_to_send);
        }
        break;
    }

    return true;
}

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}
