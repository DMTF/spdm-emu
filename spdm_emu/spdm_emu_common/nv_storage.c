/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_emu.h"

char8 *m_load_state_file_name;
char8 *m_save_state_file_name;
uint8_t m_end_session_attributes =
    SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;

/**
  Load the negotiated_state from NV storage to an SPDM context.
*/
return_status spdm_load_negotiated_state(IN void *spdm_context,
                     IN boolean is_requester)
{
    boolean ret;
    void *file_data;
    uintn file_size;
    spdm_negotiated_state_struct_t negotiated_state;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    spdm_version_number_t spdm_version;

    if (m_load_state_file_name == NULL) {
        return RETURN_UNSUPPORTED;
    }
    ret = read_input_file(m_load_state_file_name, &file_data, &file_size);
    if (!ret) {
        printf("LoadState fail - read file error\n");
        return RETURN_DEVICE_ERROR;
    }

    if (file_size != sizeof(negotiated_state)) {
        printf("LoadState fail - size mismatch\n");
        free(file_data);
        return RETURN_UNSUPPORTED;
    }

    copy_mem(&negotiated_state, file_data, file_size);
    free(file_data);

    if (negotiated_state.signature !=
        SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE) {
        printf("LoadState fail - signature mismatch\n");
        return RETURN_UNSUPPORTED;
    }
    if (negotiated_state.version != SPDM_NEGOTIATED_STATE_STRUCT_VERSION) {
        printf("LoadState fail - version mismatch\n");
        return RETURN_UNSUPPORTED;
    }

    printf("LoadState from %s\n", m_load_state_file_name);

    
    /* Override local setting*/
    
    m_use_version = negotiated_state.spdm_version;
    m_use_requester_capability_flags = negotiated_state.requester_cap_flags;
    m_use_responder_capability_flags = negotiated_state.responder_cap_flags;
    if (is_requester) {
        m_use_capability_flags = negotiated_state.requester_cap_flags;
    } else {
        m_use_capability_flags = negotiated_state.responder_cap_flags;
    }
    m_support_measurement_spec = negotiated_state.measurement_spec;
    m_support_measurement_hash_algo =
        negotiated_state.measurement_hash_algo;
    m_support_asym_algo = negotiated_state.base_asym_algo;
    m_support_hash_algo = negotiated_state.base_hash_algo;
    m_support_dhe_algo = negotiated_state.dhe_named_group;
    m_support_aead_algo = negotiated_state.aead_cipher_suite;
    m_support_req_asym_algo = negotiated_state.req_base_asym_alg;
    m_support_key_schedule_algo = negotiated_state.key_schedule;

    
    /* Set connection info*/
    
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    spdm_version.major_version = (m_use_version >> 4) & 0xF;
    spdm_version.minor_version = m_use_version & 0xF;
    spdm_version.alpha = 0;
    spdm_version.update_version_number = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
              &spdm_version, sizeof(spdm_version));

    data8 = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
              &parameter, &data8, sizeof(data8));
    if (is_requester) {
        data32 = negotiated_state.responder_cap_flags;
    } else {
        data32 = negotiated_state.requester_cap_flags;
    }
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
              &data32, sizeof(data32));

    data8 = m_support_measurement_spec;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
              &data8, sizeof(data8));
    data32 = m_support_measurement_hash_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
              &data32, sizeof(data32));
    data32 = m_support_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
              &data32, sizeof(data32));
    data32 = m_support_hash_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
              &data32, sizeof(data32));
    if (m_use_version >= SPDM_MESSAGE_VERSION_11) {
        data16 = m_support_dhe_algo;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP,
                  &parameter, &data16, sizeof(data16));
        data16 = m_support_aead_algo;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                  &parameter, &data16, sizeof(data16));
        data16 = m_support_req_asym_algo;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                  &parameter, &data16, sizeof(data16));
        data16 = m_support_key_schedule_algo;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter,
                  &data16, sizeof(data16));
    } else {
        data16 = 0;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP,
                  &parameter, &data16, sizeof(data16));
        data16 = 0;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                  &parameter, &data16, sizeof(data16));
        data16 = 0;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                  &parameter, &data16, sizeof(data16));
        data16 = 0;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter,
                  &data16, sizeof(data16));
    }

    
    /* Set connection state finally.*/
    
    data32 = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
              &data32, sizeof(data32));

    return RETURN_SUCCESS;
}

/**
  Save the negotiated_state to NV storage from an SPDM context.
*/
return_status spdm_save_negotiated_state(IN void *spdm_context,
                     IN boolean is_requester)
{
    boolean ret;
    spdm_negotiated_state_struct_t negotiated_state;
    uintn data_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    spdm_version_number_t spdm_version[SPDM_MAX_VERSION_COUNT];
    uintn index;

    if (m_save_state_file_name == NULL) {
        return RETURN_UNSUPPORTED;
    }

    m_end_session_attributes = 0;

    printf("SaveState to %s\n", m_save_state_file_name);

    zero_mem(&negotiated_state, sizeof(negotiated_state));
    negotiated_state.signature = SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE;
    negotiated_state.version = SPDM_NEGOTIATED_STATE_STRUCT_VERSION;

    
    /* get setting fron local*/
    
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    if (is_requester) {
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                  &parameter, &data32, &data_size);
        negotiated_state.requester_cap_flags = data32;
        data_size = sizeof(data8);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                  &parameter, &data8, &data_size);
        negotiated_state.requester_cap_ct_exponent = data8;
    } else {
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                  &parameter, &data32, &data_size);
        negotiated_state.responder_cap_flags = data32;
        data_size = sizeof(data8);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                  &parameter, &data8, &data_size);
        negotiated_state.responder_cap_ct_exponent = data8;
    }

    
    /* get setting fron connection*/
    
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
              &data32, &data_size);
    ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

    data_size = sizeof(spdm_version);
    zero_mem(spdm_version, sizeof(spdm_version));
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
              &spdm_version, &data_size);
    ASSERT(data_size / sizeof(spdm_version_number_t) > 0);
    index = data_size / sizeof(spdm_version_number_t) - 1;
    negotiated_state.spdm_version =
        (uint8_t)((spdm_version[index].major_version << 4) |
            spdm_version[index].minor_version);

    if (is_requester) {
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                  &parameter, &data32, &data_size);
        negotiated_state.responder_cap_flags = data32;
        data_size = sizeof(data8);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                  &parameter, &data8, &data_size);
        negotiated_state.responder_cap_ct_exponent = data8;
    } else {
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                  &parameter, &data32, &data_size);
        negotiated_state.requester_cap_flags = data32;
        data_size = sizeof(data8);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                  &parameter, &data8, &data_size);
        negotiated_state.requester_cap_ct_exponent = data8;
    }

    if ((negotiated_state.responder_cap_flags &
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP) == 0) {
        printf("responder has no cache_cap\n");
        return spdm_clear_negotiated_state(spdm_context);
    }

    data_size = sizeof(data8);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
              &data8, &data_size);
    negotiated_state.measurement_spec = data8;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
              &data32, &data_size);
    negotiated_state.measurement_hash_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
              &data32, &data_size);
    negotiated_state.base_asym_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
              &data32, &data_size);
    negotiated_state.base_hash_algo = data32;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
              &data16, &data_size);
    negotiated_state.dhe_named_group = data16;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
              &data16, &data_size);
    negotiated_state.aead_cipher_suite = data16;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
              &data16, &data_size);
    negotiated_state.req_base_asym_alg = data16;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
              &data_size);
    negotiated_state.key_schedule = data16;

    ret = write_output_file(m_save_state_file_name, &negotiated_state,
                sizeof(negotiated_state));
    if (!ret) {
        printf("SaveState fail - write file error\n");
        return RETURN_DEVICE_ERROR;
    }
    return RETURN_SUCCESS;
}

/**
  Clear the negotiated_state in the NV storage.
*/
return_status spdm_clear_negotiated_state(IN void *spdm_context)
{
    boolean ret;

    if (m_save_state_file_name == NULL) {
        return RETURN_UNSUPPORTED;
    }

    printf("ClearState in %s\n", m_save_state_file_name);

    ret = write_output_file(m_save_state_file_name, NULL, 0);
    if (!ret) {
        printf("ClearState fail - write file error\n");
        return RETURN_DEVICE_ERROR;
    }
    return RETURN_SUCCESS;
}
