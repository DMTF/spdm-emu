/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

extern void *m_spdm_context;

/**
  This function executes SPDM measurement and extend to TPM.

  @param[in]  spdm_context            The SPDM context for the device.
**/
return_status spdm_send_receive_get_measurement(IN void *spdm_context,
						IN uint32 *session_id)
{
	return_status status;
	uint8 number_of_blocks;
	uint8 number_of_block;
	uint32 measurement_record_length;
	uint8 measurement_record[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	uint8 index;
	uint8 request_attribute;

	if (m_use_measurement_operation ==
	    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
		//
		// request all at one time.
		//
		request_attribute =
			SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
		measurement_record_length = sizeof(measurement_record);
		status = spdm_get_measurement(
			spdm_context, session_id, request_attribute,
			SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
			m_use_slot_id & 0xF, &number_of_block,
			&measurement_record_length, measurement_record);
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else {
		request_attribute = 0;
		//
		// 1. query the total number of measurements available.
		//
		status = spdm_get_measurement(
			spdm_context, session_id, request_attribute,
			SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
			m_use_slot_id & 0xF, &number_of_blocks, NULL, NULL);
		if (RETURN_ERROR(status)) {
			return status;
		}
		DEBUG((DEBUG_INFO, "number_of_blocks - 0x%x\n",
		       number_of_blocks));
		for (index = 1; index <= number_of_blocks; index++) {
			DEBUG((DEBUG_INFO, "index - 0x%x\n", index));
			//
			// 2. query measurement one by one
			// get signature in last message only.
			//
			if (index == number_of_blocks) {
				request_attribute =
					SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
			}
			measurement_record_length = sizeof(measurement_record);
			status = spdm_get_measurement(
				spdm_context, session_id, request_attribute,
				index, m_use_slot_id & 0xF, &number_of_block,
				&measurement_record_length, measurement_record);
			if (RETURN_ERROR(status)) {
				return status;
			}
		}
	}

	return RETURN_SUCCESS;
}

/**
  This function executes SPDM measurement and extend to TPM.

  @param[in]  spdm_context            The SPDM context for the device.
**/
return_status do_measurement_via_spdm(IN uint32 *session_id)
{
	return_status status;
	void *spdm_context;

	spdm_context = m_spdm_context;

	status = spdm_send_receive_get_measurement(spdm_context, session_id);
	if (RETURN_ERROR(status)) {
		return status;
	}
	return RETURN_SUCCESS;
}
