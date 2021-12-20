/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_transport_none_lib.h"

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status none_encode_message(IN uint32_t *session_id, IN uintn message_size,
                  IN void *message,
                  IN OUT uintn *transport_message_size,
                  OUT void *transport_message)
{
    *transport_message_size = message_size;
    copy_mem((uint8_t *)transport_message, message, message_size);
    zero_mem((uint8_t *)transport_message + message_size,
             *transport_message_size - message_size);
    return RETURN_SUCCESS;
}

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status none_decode_message(OUT uint32_t **session_id,
                  IN uintn transport_message_size,
                  IN void *transport_message,
                  IN OUT uintn *message_size, OUT void *message)
{
    *message_size = transport_message_size;
    copy_mem(message, transport_message, transport_message_size);
    return RETURN_SUCCESS;
}

/**
  Get sequence number in an SPDM secure message.

  This value is transport layer specific.

  @param sequence_number        The current sequence number used to encode or decode message.
  @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
                               The size in byte of the output buffer shall be 8.

  @return size in byte of the sequence_number_buffer.
          It shall be no greater than 8.
          0 means no sequence number is required.
**/
uint8_t spdm_none_get_sequence_number(IN uint64_t sequence_number,
                    IN OUT uint8_t *sequence_number_buffer)
{
    return 0;
}

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
uint32_t spdm_none_get_max_random_number_count(void)
{
    return 0;
}
