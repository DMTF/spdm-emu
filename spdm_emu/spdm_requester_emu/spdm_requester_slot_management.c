/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

extern void *m_spdm_context;

/**
 * Issue the SLOT_MANAGEMENT GetCSR SubCode for a Bank+slot, if the Responder supports it.
 *
 * GetCSR reuses the GET_CSR HAL hook, so it is only meaningful when CSR_CAP is
 * enabled. It is gated on the GetCSR bit in the SubCode bit map.
 **/
static libspdm_return_t do_slot_management_get_csr(
    void *spdm_context, const uint32_t *session_id,
    const uint8_t *sub_code_bitmap, uint8_t bank_id, uint8_t slot_id)
{
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    libspdm_return_t status;
    uint8_t *csr;
    size_t csr_len;
    uint8_t key_pair_id;
    uint8_t request_attributes;
    bool multi_key_conn_rsp;
    libspdm_data_parameter_t parameter;
    size_t data_size;

    if ((sub_code_bitmap[SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR / 8] &
         (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR % 8))) == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    /* In a multi-key connection the request shall carry a KeyPairID and a certificate model;
     * otherwise both shall be 0 (matching the legacy GET_CSR flow). */
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(multi_key_conn_rsp);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                     &multi_key_conn_rsp, &data_size);
    if (multi_key_conn_rsp) {
        key_pair_id = 1;
        request_attributes = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    } else {
        key_pair_id = 0;
        request_attributes = 0;
    }

    csr = (uint8_t *)malloc(LIBSPDM_MAX_CSR_SIZE);
    if (csr == NULL) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }
    csr_len = LIBSPDM_MAX_CSR_SIZE;

    status = libspdm_slot_management_get_csr(
        spdm_context, session_id, bank_id, slot_id, key_pair_id, request_attributes,
        NULL, 0, NULL, 0, csr, &csr_len);

    free(csr);
    return status;
#else /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
    return LIBSPDM_STATUS_SUCCESS;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
}

/**
 * Issue the SLOT_MANAGEMENT SetCertificate SubCode for a Bank+slot, if the Responder supports
 * it. The certificate chain to write is read from the responder sample certificates.
 *
 * SetCertificate reuses the SET_CERTIFICATE HAL hook, so it is only meaningful when SET_CERT_CAP
 * is enabled. It is gated on the SetCertificate bit in the SubCode bit map.
 **/
static libspdm_return_t do_slot_management_set_certificate(
    void *spdm_context, const uint32_t *session_id,
    const uint8_t *sub_code_bitmap, uint8_t bank_id, uint8_t slot_id)
{
#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    libspdm_return_t status;
    void *cert_chain;
    size_t cert_chain_size;
    bool res;
    bool multi_key_conn_rsp;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    uint8_t cert_attributes;

    if ((sub_code_bitmap[SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE / 8] &
         (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE % 8))) == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    cert_chain = NULL;
    cert_chain_size = 0;
    res = false;
    if (m_use_asym_algo != 0) {
        res = libspdm_read_responder_public_certificate_chain(
            m_use_hash_algo, m_use_asym_algo, &cert_chain, &cert_chain_size, NULL, NULL);
    } else if (m_use_pqc_asym_algo != 0) {
        res = libspdm_read_pqc_responder_public_certificate_chain(
            m_use_hash_algo, m_use_pqc_asym_algo, &cert_chain, &cert_chain_size, NULL, NULL);
    }
    if (!res) {
        EMU_ERR("set certificate: read_responder_public_certificate_chain fail!\n");
        if (cert_chain != NULL) {
            free(cert_chain);
        }
        return LIBSPDM_STATUS_INVALID_CERT;
    }

    /* In a multi-key connection the request shall carry a certificate model. */
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(multi_key_conn_rsp);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                     &multi_key_conn_rsp, &data_size);
    if (multi_key_conn_rsp) {
        cert_attributes = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    } else {
        cert_attributes = 0;
    }

    status = libspdm_slot_management_set_certificate(
        spdm_context, session_id, bank_id, slot_id, cert_attributes,
        cert_chain, cert_chain_size);

    free(cert_chain);
    return status;
#else /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
    return LIBSPDM_STATUS_SUCCESS;
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
}

/**
 * This function executes SPDM SLOT_MANAGEMENT for the full set of SubCodes the Responder
 * advertises: SupportedSubCodes, GetBankInfo, GetBankDetails, GetCertificateChain, GetCSR,
 * ManageBank, SetCertificate, and ManageSlot.
 *
 * @param[in]  session_id              Indicates if it is a secured message protected via SPDM
 *                                     session. If session_id is NULL, it is a normal message.
 **/
libspdm_return_t do_slot_management_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;

    uint8_t sub_code_bitmap[8];
    /* BankID is limited to 0-239 by the specification, so SPDM_MAX_BANK_COUNT BankElements can
     * hold every possible Bank. */
    spdm_slot_management_bank_element_struct_t bank_elements[SPDM_MAX_BANK_COUNT];
    uint8_t num_bank_elements;
    uint8_t bank_index;

    spdm_context = m_spdm_context;

    libspdm_zero_mem(sub_code_bitmap, sizeof(sub_code_bitmap));

    /* SupportedSubCodes: discover which SubCodes the Responder supports. */
    status = libspdm_slot_management_get_supported_subcodes(spdm_context, session_id,
                                                            sub_code_bitmap);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    /* GetBankInfo: enumerate the Banks the Responder exposes. */
    if ((sub_code_bitmap[0] & (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO)) == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    num_bank_elements = LIBSPDM_ARRAY_SIZE(bank_elements);
    status = libspdm_slot_management_get_bank_info(spdm_context, session_id,
                                                   &num_bank_elements, bank_elements);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (bank_index = 0; bank_index < num_bank_elements; bank_index++) {
        uint8_t bank_id;
        uint8_t slot_mask;
        uint8_t slot_id;
        uint8_t first_slot_id;
        bool first_slot_found;
        uint32_t current_asym_algo = 0;

        bank_id = bank_elements[bank_index].bank_id;
        slot_mask = bank_elements[bank_index].slot_mask;

        first_slot_found = false;
        first_slot_id = 0;
        for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
            if ((slot_mask & (1 << slot_id)) != 0) {
                first_slot_id = slot_id;
                first_slot_found = true;
                break;
            }
        }

        /* GetBankDetails: read the per-slot details of this Bank. */
        if ((sub_code_bitmap[0] &
             (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS)) != 0) {
            uint8_t bank_attributes;
            uint16_t num_slot_elements;

            status = libspdm_slot_management_get_bank_details(
                spdm_context, session_id, bank_id, &bank_attributes,
                NULL, &current_asym_algo, NULL, NULL, NULL, NULL,
                &num_slot_elements, NULL, NULL);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }

        /* ManageBank: re-configure the Bank to its current asymmetric algorithm. This is
         * idempotent, so it exercises the ManageBank SubCode without changing the device
         * configuration. */
        if (((sub_code_bitmap[SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK / 8] &
              (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK % 8))) != 0) &&
            (current_asym_algo != 0)) {
            status = libspdm_slot_management_manage_bank(
                spdm_context, session_id, bank_id,
                SPDM_SLOT_MANAGEMENT_MANAGE_BANK_OPERATION_CONFIG_ALGO,
                current_asym_algo, 0);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }

        /* GetCertificateChain: read the certificate chain of each provisioned slot. */
        if ((sub_code_bitmap[0] &
             (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN)) != 0) {
            uint8_t *cert_chain;

            cert_chain = (uint8_t *)malloc(LIBSPDM_MAX_CERT_CHAIN_SIZE);
            if (cert_chain == NULL) {
                return LIBSPDM_STATUS_BUFFER_FULL;
            }

            for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
                size_t cert_chain_size;

                if ((slot_mask & (1 << slot_id)) == 0) {
                    continue;
                }

                cert_chain_size = LIBSPDM_MAX_CERT_CHAIN_SIZE;
                status = libspdm_slot_management_get_certificate_chain(
                    spdm_context, session_id, bank_id, slot_id,
                    &cert_chain_size, cert_chain);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    free(cert_chain);
                    return status;
                }
            }

            free(cert_chain);
        }

        if (!first_slot_found) {
            continue;
        }

        /* GetCSR: read a certificate signing request from the first provisioned slot. */
        status = do_slot_management_get_csr(spdm_context, session_id, sub_code_bitmap,
                                            bank_id, first_slot_id);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        /* SetCertificate: re-provision the certificate chain of the first provisioned slot.
         * The sample stores the chain per slot, so writing it back leaves the slot usable.
         * SetCertificate to a non-zero Bank is only allowed in a trusted environment (the
         * Responder rejects it otherwise), so this exercises Bank 0 only. */
        if (bank_id == 0) {
            status = do_slot_management_set_certificate(spdm_context, session_id,
                                                        sub_code_bitmap, bank_id, first_slot_id);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
    }

    /* ManageSlot (Erase): exercised last because it removes a slot's certificate chain, which
     * changes the SlotMask the Responder reports for subsequent SubCodes. Erase the first
     * provisioned slot of the last enumerated Bank, leaving Bank 0 (used by the other SubCodes
     * above) untouched. */
    if ((sub_code_bitmap[SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT / 8] &
         (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT % 8))) != 0) {
        for (bank_index = num_bank_elements; bank_index > 0; bank_index--) {
            uint8_t bank_id;
            uint8_t slot_mask;
            uint8_t slot_id;

            bank_id = bank_elements[bank_index - 1].bank_id;
            slot_mask = bank_elements[bank_index - 1].slot_mask;

            if (slot_mask == 0) {
                continue;
            }

            for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
                if ((slot_mask & (1 << slot_id)) == 0) {
                    continue;
                }
                status = libspdm_slot_management_manage_slot(
                    spdm_context, session_id, bank_id, slot_id,
                    SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return status;
                }
                break;
            }
            break;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP*/
