/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_none_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "hal/library/debuglib.h"

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
 * @retval LIBSPDM_STATUS_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t none_encode_message(const uint32_t *session_id, size_t message_size,
                                  const void *message,
                                  size_t *transport_message_size,
                                  void **transport_message);

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
 * @retval LIBSPDM_STATUS_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t none_decode_message(uint32_t **session_id,
                                  size_t transport_message_size,
                                  const void *transport_message,
                                  size_t *message_size,
                                  void **message);

/**
 * Encode an SPDM from a transport layer message.
 *
 * Only for normal SPDM message, it adds the transport layer wrapper.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     On input, it shall be msg_buf_ptr from receiver buffer.
 *                                     On output, for normal message, it will point to the original receiver buffer.
 *                                     On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is invalid.
 **/
libspdm_return_t spdm_transport_none_encode_message(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message)
{
    libspdm_return_t status;

    if (is_app_message && (session_id == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    /* normal message */
    status = none_encode_message(NULL, message_size, message,
                                transport_message_size,
                                transport_message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %p\n",
                        status));
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode an SPDM from a transport layer message.
 *
 * Only for normal SPDM message, it removes the transport layer wrapper.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     On input, it shall be msg_buf_ptr from receiver buffer.
 *                                     On output, for normal message, it will point to the original receiver buffer.
 *                                     On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is invalid.
 **/
libspdm_return_t spdm_transport_none_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message)
{
    
    libspdm_return_t status;

    if ((session_id == NULL) || (is_app_message == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    
    /* get non-secured message*/
    status = none_decode_message(NULL,
                                transport_message_size,
                                transport_message,
                                message_size, message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %p\n",
                        status));
        return status;
    }

    *session_id = NULL;
    *is_app_message = false;
    return LIBSPDM_STATUS_SUCCESS;
}

