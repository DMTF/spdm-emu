/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_attester_sample.h"

/**
 * This function sends GET_DIGEST, GET_CERTIFICATE, CHALLENGE
 * to authenticate the device.
 *
 * This function is combination of libspdm_get_digest, libspdm_get_certificate, libspdm_challenge.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_mask                     The slots which deploy the CertificateChain.
 * @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
 *                                     On output, indicate the size in bytes of the certificate chain.
 * @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The authentication is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t
spdm_authentication(void *context, uint8_t *slot_mask,
                    spdm_attester_cert_chain_struct_t cert_chain[SPDM_MAX_SLOT_COUNT])
{
    libspdm_return_t status;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t slot_id;

    status = libspdm_get_digest(context, slot_mask,
                                total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((*slot_mask & (1 << slot_id)) == 0) {
            cert_chain[slot_id].cert_chain_size = 0;
            continue;
        }
        cert_chain[slot_id].cert_chain_size = sizeof(cert_chain[slot_id].cert_chain);
        status = libspdm_get_certificate(
                    context, slot_id,
                    &cert_chain[slot_id].cert_chain_size,
                    cert_chain[slot_id].cert_chain);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    status = libspdm_challenge(context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                               NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
