/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

extern SOCKET m_socket;

extern void *m_spdm_context;

boolean communicate_platform_data(IN SOCKET socket, IN uint32_t command,
				  IN uint8_t *send_buffer, IN uintn bytes_to_send,
				  OUT uint32_t *response,
				  IN OUT uintn *bytes_to_receive,
				  OUT uint8_t *receive_buffer);

return_status do_measurement_via_spdm(IN uint32_t *session_id);

spdm_vendor_defined_request_mine_t mVendorDefinedRequest = {
	{
		SPDM_MESSAGE_VERSION_10, SPDM_VENDOR_DEFINED_REQUEST,
		0, // param1
		0, // param2
	},
	SPDM_REGISTRY_ID_PCISIG, // standard_id
	2, // len
	SPDM_VENDOR_ID_PCISIG, // vendor_id
	sizeof(pci_protocol_header_t) +
		sizeof(pci_ide_km_query_t), // payload_length
	{
		PCI_PROTOCAL_ID_IDE_KM,
	},
	{
		{
			PCI_IDE_KM_OBJECT_ID_QUERY,
		},
		0, // reserved
		0, // port_index
	}
};

secure_session_request_mine_t mSecureSessionRequest = {
	{ MCTP_MESSAGE_TYPE_PLDM },
	{
		0x80,
		PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
		PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
	},
};

return_status do_app_session_via_spdm(IN uint32_t session_id)
{
	void *spdm_context;
	return_status status;
	spdm_vendor_defined_request_mine_t request;
	uintn request_size;
	spdm_vendor_defined_response_mine_t response;
	uintn response_size;
	secure_session_response_mine_t app_response;
	uintn app_response_size;

	spdm_context = m_spdm_context;

	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
		copy_mem(&request, &mVendorDefinedRequest, sizeof(request));

		request_size = sizeof(request);
		response_size = sizeof(response);
		status = libspdm_send_receive_data(spdm_context, &session_id,
						FALSE, &request, request_size,
						&response, &response_size);
		ASSERT_RETURN_ERROR(status);

		ASSERT(response_size ==
		       sizeof(spdm_vendor_defined_response_mine_t));
		ASSERT(response.header.request_response_code ==
		       SPDM_VENDOR_DEFINED_RESPONSE);
		ASSERT(response.standard_id == SPDM_REGISTRY_ID_PCISIG);
		ASSERT(response.vendor_id == SPDM_VENDOR_ID_PCISIG);
		ASSERT(response.payload_length ==
		       sizeof(pci_protocol_header_t) +
			       sizeof(pci_ide_km_query_resp_t));
		ASSERT(response.pci_protocol.protocol_id ==
		       PCI_PROTOCAL_ID_IDE_KM);
		ASSERT(response.pci_ide_km_query_resp.header.object_id ==
		       PCI_IDE_KM_OBJECT_ID_QUERY_RESP);
	}

	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
		app_response_size = sizeof(app_response);
		status = libspdm_send_receive_data(spdm_context, &session_id, TRUE,
						&mSecureSessionRequest,
						sizeof(mSecureSessionRequest),
						&app_response,
						&app_response_size);
		ASSERT_RETURN_ERROR(status);

		ASSERT(app_response_size == sizeof(app_response));
		ASSERT(app_response.mctp_header.message_type ==
		       MCTP_MESSAGE_TYPE_PLDM);
		ASSERT(app_response.pldm_header.pldm_type ==
		       PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
		ASSERT(app_response.pldm_header.pldm_command_code ==
		       PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);
		ASSERT(app_response.pldm_response_header.pldm_completion_code ==
		       PLDM_BASE_CODE_SUCCESS);
	}

	return RETURN_SUCCESS;
}

return_status do_session_via_spdm(IN boolean use_psk)
{
	void *spdm_context;
	return_status status;
	uint32_t session_id;
	uint8_t heartbeat_period;
	uint8_t measurement_hash[MAX_HASH_SIZE];
	uintn response_size;
	boolean result;
	uint32_t response;

	spdm_context = m_spdm_context;

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = libspdm_start_session(spdm_context, use_psk,
				    m_use_measurement_summary_hash_type,
				    m_use_slot_id, &session_id,
				    &heartbeat_period, measurement_hash);
	if (RETURN_ERROR(status)) {
		printf("libspdm_start_session - %x\n", (uint32_t)status);
		return status;
	}

	do_app_session_via_spdm(session_id);

	if ((m_exe_session & EXE_SESSION_HEARTBEAT) != 0) {
		status = libspdm_heartbeat(spdm_context, session_id);
		if (RETURN_ERROR(status)) {
			printf("libspdm_heartbeat - %x\n", (uint32_t)status);
		}
	}

	if ((m_exe_session & EXE_SESSION_KEY_UPDATE) != 0) {
		switch (m_use_key_update_action) {
		case SPDM_KEY_UPDATE_ACTION_REQUESTER:
			status =
				libspdm_key_update(spdm_context, session_id, TRUE);
			if (RETURN_ERROR(status)) {
				printf("libspdm_key_update - %x\n",
				       (uint32_t)status);
			}
			break;

		case SPDM_KEY_UPDATE_ACTION_ALL:
			status = libspdm_key_update(spdm_context, session_id,
						 FALSE);
			if (RETURN_ERROR(status)) {
				printf("libspdm_key_update - %x\n",
				       (uint32_t)status);
			}
			break;

		case SPDM_KEY_UPDATE_ACTION_RESPONDER:
			response_size = 0;
			result = communicate_platform_data(
				m_socket,
				SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL,
				0, &response, &response_size, NULL);
			if (!result) {
				printf("communicate_platform_data - SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE fail\n");
			} else {
				status = libspdm_send_receive_encap_request(
					spdm_context, &session_id);
				if (RETURN_ERROR(status)) {
					printf("libspdm_send_receive_encap_request - libspdm_key_update - %x\n",
					       (uint32_t)status);
				}
			}
			break;

		default:
			ASSERT(FALSE);
			break;
		}
	}

	if ((m_exe_session & EXE_SESSION_MEAS) != 0) {
		status = do_measurement_via_spdm(&session_id);
		if (RETURN_ERROR(status)) {
			printf("do_measurement_via_spdm - %x\n",
			       (uint32_t)status);
		}
	}

	if ((m_exe_session & EXE_SESSION_NO_END) == 0) {
		status = libspdm_stop_session(spdm_context, session_id,
					   m_end_session_attributes);
		if (RETURN_ERROR(status)) {
			printf("libspdm_stop_session - %x\n", (uint32_t)status);
			return status;
		}
	}

	return status;
}