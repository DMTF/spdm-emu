/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"

#if LIBSPDM_ECDSA_SUPPORT
#include "bin/ecp384_bundle_responder_certchain.c"
#endif

#include "bin/ecp384_root_ca.c"

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (base_asym_algo == 0) {
        return false;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);
#if LIBSPDM_SHA384_SUPPORT
    LIBSPDM_ASSERT(digest_size == LIBSPDM_SHA384_DIGEST_SIZE);
#endif

    switch (base_asym_algo) {
#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        cert_chain = (void *)m_libspdm_ecp384_bundle_responder_certchain;
        cert_chain_size = sizeof(m_libspdm_ecp384_bundle_responder_certchain);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    /* patch */
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    /* Get Root Certificate and calculate hash value*/

    root_cert = m_libspdm_ec384_responder_root_ca;
    root_cert_len = sizeof(m_libspdm_ec384_responder_root_ca);

    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        return res;
    }
    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    return true;
}
