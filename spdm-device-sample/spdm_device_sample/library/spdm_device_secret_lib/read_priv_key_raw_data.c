/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
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

#if LIBSPDM_ECDSA_SUPPORT
#include "bin/ecp384_raw_key.c"
#endif /*LIBSPDM_ECDSA_SUPPORT*/

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
    bool result;

#if LIBSPDM_ECDSA_SUPPORT
    void *ec_context;
    size_t ec_nid;
    uint8_t *ec_public;
    uint8_t *ec_private;
    size_t ec_public_size;
    size_t ec_private_size;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

    switch (base_asym_algo) {
#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
        ec_public = m_libspdm_ec384_responder_public_key;
        ec_private = m_libspdm_ec384_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec384_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec384_responder_private_key);
        break;
#endif /*LIBSPDM_ECDSA_SUPPORT*/
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
#if LIBSPDM_ECDSA_SUPPORT
        ec_context = libspdm_ec_new_by_nid(ec_nid);
        if (ec_context == NULL) {
            return false;
        }
        result = libspdm_ec_set_pub_key(ec_context, ec_public, ec_public_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        result = libspdm_ec_set_priv_key(ec_context, ec_private, ec_private_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        *context = ec_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /*#LIBSPDM_ECDSA_SUPPORT*/
    }

    return false;
}

