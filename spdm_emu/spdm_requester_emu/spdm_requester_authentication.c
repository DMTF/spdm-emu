/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

extern void *m_spdm_context;

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
                    void *total_digest_buffer, uint8_t slot_id,
                    size_t *cert_chain_size, void *cert_chain,
                    uint8_t measurement_hash_type, void *measurement_hash)
{
    libspdm_return_t status;
    size_t cert_chain_buffer_size;

    if ((m_exe_connection & EXE_CONNECTION_DIGEST) != 0) {
        status = libspdm_get_digest(context, slot_mask,
                                    total_digest_buffer);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    if ((m_exe_connection & EXE_CONNECTION_CERT) != 0) {
        if (slot_id != 0xFF) {
            if (slot_id == 0) {
                cert_chain_buffer_size = *cert_chain_size;
                status = libspdm_get_certificate(
                    context, 0, cert_chain_size, cert_chain);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return status;
                }
                *cert_chain_size = cert_chain_buffer_size;
                libspdm_zero_mem(cert_chain, cert_chain_buffer_size);
                status = libspdm_get_certificate(
                    context, 1, cert_chain_size, cert_chain);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return status;
                }
            } else {
                status = libspdm_get_certificate(
                    context, slot_id, cert_chain_size, cert_chain);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return status;
                }
            }
        }
    }

    if ((m_exe_connection & EXE_CONNECTION_CHAL) != 0) {
        status = libspdm_challenge(context, slot_id, measurement_hash_type,
                                   measurement_hash, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    if ((m_exe_connection & EXE_CONNECTION_DIGEST) != 0) {
        status = libspdm_get_digest(context, slot_mask,
                                    total_digest_buffer);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    if ((m_exe_connection & EXE_CONNECTION_CERT) != 0) {
        if (slot_id != 0xFF) {
            status = libspdm_get_certificate(
                context, slot_id, cert_chain_size, cert_chain);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
    }

    if ((m_exe_connection & EXE_CONNECTION_DIGEST) != 0) {
        status = libspdm_get_digest(context, slot_mask,
                                    total_digest_buffer);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM authentication.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_authentication_via_spdm(void)
{
    libspdm_return_t status;
    void *spdm_context;
    uint8_t slot_mask;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_context = m_spdm_context;

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_authentication(spdm_context, &slot_mask,
                                 &total_digest_buffer, m_use_slot_id,
                                 &cert_chain_size, cert_chain,
                                 m_use_measurement_summary_hash_type,
                                 measurement_hash);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/
