/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_none_lib.h"

/**
 * Get sequence number in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @param sequence_number        The current sequence number used to encode or decode message.
 * @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
 *                             The size in byte of the output buffer shall be 8.
 *
 * @return size in byte of the sequence_number_buffer.
 *        It shall be no greater than 8.
 *        0 means no sequence number is required.
 **/
uint8_t spdm_none_get_sequence_number(uint64_t sequence_number,
                                      uint8_t *sequence_number_buffer)
{
    return 0;
}

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no randum number is required.
 **/
uint32_t spdm_none_get_max_random_number_count(void)
{
    return 0;
}

/**
 * Encode a normal message or secured message to a transport message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 *                                     For normal message, it will point to the acquired sender buffer.
 *                                     For secured message, it will point to the scratch buffer in spdm_context.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *                                     For normal message or secured message, it will point to acquired sender buffer.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
return_status none_encode_message(const uint32_t *session_id, size_t message_size,
                                  const void *message,
                                  size_t *transport_message_size,
                                  void **transport_message)
{
    *transport_message_size = message_size;
    *transport_message = (void *)message;
    return RETURN_SUCCESS;
}

/**
 * Decode a transport message to a normal message or secured message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it will point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     For normal message, it will point to the original receiver buffer.
 *                                     For secured message, it will point to the scratch buffer in spdm_context.
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
return_status none_decode_message(uint32_t **session_id,
                                  size_t transport_message_size,
                                  const void *transport_message,
                                  size_t *message_size, void **message)
{
    *message_size = transport_message_size;
    *message = (void *)transport_message;
    return RETURN_SUCCESS;
}

/**
 * Return the maximum transport layer message header size.
 *  Transport Message Header Size + sizeof(spdm_secured_message_cipher_header_t))
 *
 *  For MCTP, Transport Message Header Size = sizeof(mctp_message_header_t)
 *  For PCI_DOE, Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return size of maximum transport layer message header size
 **/
uint32_t spdm_transport_none_get_header_size(
    void *spdm_context)
{
    return sizeof(spdm_secured_message_cipher_header_t);
}
