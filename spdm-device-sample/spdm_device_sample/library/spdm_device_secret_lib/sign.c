/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/
#include <base.h>
#if defined(_MSC_VER) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
    defined(LIBSPDM_CPU_ARM)))
#else
/*    #include <fcntl.h>
 *    #include <unistd.h>
 *    #include <sys/stat.h> */
#endif
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"

/**
 * Sign an SPDM message data.
 *
 * @param  base_asym_algo                 Indicates the signing algorithm.
 * @param  base_hash_algo                 Indicates the hash algorithm.
 * @param  message                      A pointer to a message to be signed (before hash).
 * @param  message_size                  The size in bytes of the message to be signed.
 * @param  signature                    A pointer to a destination buffer to store the signature.
 * @param  sig_size                      On input, indicates the size in bytes of the destination buffer to store the signature.
 *                                     On output, indicates the size in bytes of the signature in the buffer.
 *
 * @retval true  signing success.
 * @retval false signing fail.
 **/
bool libspdm_responder_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;

    result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                        context,
                                        message, message_size, signature, sig_size);
    } else {
        result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo, base_hash_algo, context,
                                   message, message_size, signature, sig_size);
    }
    libspdm_asym_free(base_asym_algo, context);

    return result;
}
