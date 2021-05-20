/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#ifndef __SPDM_EMU_NV_STORAGE_LIB_H__
#define __SPDM_EMU_NV_STORAGE_LIB_H__

#include <base.h>
#include <industry_standard/spdm.h>

#define SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE SIGNATURE_32('S', 'P', 'D', 'M')
#define SPDM_NEGOTIATED_STATE_STRUCT_VERSION 1

#pragma pack(1)
typedef struct {
	uint32 signature;
	uint32 version;
	uint8 spdm_version;
	uint8 requester_cap_ct_exponent;
	uint32 requester_cap_flags;
	uint8 responder_cap_ct_exponent;
	uint32 responder_cap_flags;
	uint8 measurement_spec;
	uint32 measurement_hash_algo;
	uint32 base_asym_algo;
	uint32 base_hash_algo;
	uint16 dhe_named_group;
	uint16 aead_cipher_suite;
	uint16 req_base_asym_alg;
	uint16 key_schedule;
} spdm_negotiated_state_struct_t;
#pragma pack()

/**
  Load the negotiated_state from NV storage to an SPDM context.
*/
return_status spdm_load_negotiated_state(IN void *spdm_context,
					 IN boolean is_requester);

/**
  Save the negotiated_state to NV storage from an SPDM context.
*/
return_status spdm_save_negotiated_state(IN void *spdm_context,
					 IN boolean is_requester);

/**
  Clear the negotiated_state in the NV storage.
*/
return_status spdm_clear_negotiated_state(IN void *spdm_context);

#endif