/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_emu.h"

void *m_spdm_context;

extern uint32 m_command;
extern uintn m_receive_buffer_size;
extern uint8 m_receive_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern SOCKET m_server_socket;

/**
  Notify the session state to a session APP.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The session_id of a session.
  @param  session_state                 The state of a session.
**/
void spdm_server_session_state_callback(IN void *spdm_context,
					IN uint32 session_id,
					IN spdm_session_state_t session_state);

/**
  Notify the connection state to an SPDM context register.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  connection_state              Indicate the SPDM connection state.
**/
void spdm_server_connection_state_callback(
	IN void *spdm_context, IN spdm_connection_state_t connection_state);

return_status spdm_get_response_vendor_defined_request(
	IN void *spdm_context, IN uint32 *session_id, IN boolean is_app_message,
	IN uintn request_size, IN void *request, IN OUT uintn *response_size,
	OUT void *response);

return_status spdm_device_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64 timeout)
{
	boolean result;

	result = send_platform_data(m_server_socket, SOCKET_SPDM_COMMAND_NORMAL,
				    request, (uint32)request_size);
	if (!result) {
		printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return RETURN_DEVICE_ERROR;
	}
	return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context,
					  IN OUT uintn *response_size,
					  IN OUT void *response,
					  IN uint64 timeout)
{
	boolean result;

	m_receive_buffer_size = sizeof(m_receive_buffer);
	result =
		receive_platform_data(m_server_socket, &m_command,
				      m_receive_buffer, &m_receive_buffer_size);
	if (!result) {
		printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return RETURN_DEVICE_ERROR;
	}
	if (m_command == SOCKET_SPDM_COMMAND_NORMAL) {
		//
		// Cache the message in case it is not for SPDM.
		//
	} else {
		//
		// Cache the message
		//
		return RETURN_UNSUPPORTED;
	}
	if (*response_size < m_receive_buffer_size) {
		*response_size = m_receive_buffer_size;
		return RETURN_BUFFER_TOO_SMALL;
	}
	*response_size = m_receive_buffer_size;
	copy_mem(response, m_receive_buffer, m_receive_buffer_size);
	return RETURN_SUCCESS;
}

void *spdm_server_init(void)
{
	void *spdm_context;
	spdm_data_parameter_t parameter;
	uint8 data8;
	uint16 data16;
	uint32 data32;
	spdm_version_number_t spdm_version;

	printf("context_size - 0x%x\n", (uint32)spdm_get_context_size());

	m_spdm_context = (void *)malloc(spdm_get_context_size());
	if (m_spdm_context == NULL) {
		return NULL;
	}
	spdm_context = m_spdm_context;
	spdm_init_context(spdm_context);
	spdm_register_device_io_func(spdm_context, spdm_device_send_message,
				     spdm_device_receive_message);
	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
		spdm_register_transport_layer_func(
			spdm_context, spdm_transport_mctp_encode_message,
			spdm_transport_mctp_decode_message);
	} else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
		spdm_register_transport_layer_func(
			spdm_context, spdm_transport_pci_doe_encode_message,
			spdm_transport_pci_doe_decode_message);
	} else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
		spdm_register_transport_layer_func(
			spdm_context, spdm_transport_none_encode_message,
			spdm_transport_none_decode_message);
	} else {
		return NULL;
	}

	if (m_load_state_file_name != NULL) {
		spdm_load_negotiated_state(spdm_context, FALSE);
	}

	if (m_use_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		spdm_version.major_version = (m_use_version >> 4) & 0xF;
		spdm_version.minor_version = m_use_version & 0xF;
		spdm_version.alpha = 0;
		spdm_version.update_version_number = 0;
		spdm_set_data(spdm_context, SPDM_DATA_SPDM_VERSION, &parameter,
			      &spdm_version, sizeof(spdm_version));
	}

	if (m_use_secured_message_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		if (m_use_secured_message_version != 0) {
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_version.major_version =
				(m_use_secured_message_version >> 4) & 0xF;
			spdm_version.minor_version =
				m_use_secured_message_version & 0xF;
			spdm_version.alpha = 0;
			spdm_version.update_version_number = 0;
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, &spdm_version,
				      sizeof(spdm_version));
		} else {
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, NULL, 0);
		}
	}

	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_LOCAL;

	data8 = 0;
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT,
		      &parameter, &data8, sizeof(data8));
	data32 = m_use_responder_capability_flags;
	if (m_use_capability_flags != 0) {
		data32 = m_use_capability_flags;
	}
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter,
		      &data32, sizeof(data32));

	data8 = m_support_measurement_spec;
	spdm_set_data(spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter,
		      &data8, sizeof(data8));
	data32 = m_support_measurement_hash_algo;
	spdm_set_data(spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
		      &data32, sizeof(data32));
	data32 = m_support_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, sizeof(data32));
	data32 = m_support_hash_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, sizeof(data32));
	data16 = m_support_dhe_algo;
	spdm_set_data(spdm_context, SPDM_DATA_DHE_NAME_GROUP, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_aead_algo;
	spdm_set_data(spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_req_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_key_schedule_algo;
	spdm_set_data(spdm_context, SPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
		      sizeof(data16));

	spdm_register_get_response_func(
		spdm_context, spdm_get_response_vendor_defined_request);

	spdm_register_session_state_callback_func(
		spdm_context, spdm_server_session_state_callback);
	spdm_register_connection_state_callback_func(
		spdm_context, spdm_server_connection_state_callback);

	if (m_load_state_file_name != NULL) {
		// Invoke callback to provision the rest
		spdm_server_connection_state_callback(
			spdm_context, SPDM_CONNECTION_STATE_NEGOTIATED);
	}

	return m_spdm_context;
}

/**
  Notify the connection state to an SPDM context register.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  connection_state              Indicate the SPDM connection state.
**/
void spdm_server_connection_state_callback(
	IN void *spdm_context, IN spdm_connection_state_t connection_state)
{
	boolean res;
	void *data;
	uintn data_size;
	spdm_data_parameter_t parameter;
	uint8 data8;
	uint16 data16;
	uint32 data32;
	return_status status;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uint8 index;

	switch (connection_state) {
	case SPDM_CONNECTION_STATE_NOT_STARTED:
		//
		// clear perserved state
		//
		if (m_save_state_file_name != NULL) {
			spdm_clear_negotiated_state(spdm_context);
		}
		break;

	case SPDM_CONNECTION_STATE_NEGOTIATED:
		//
		// Provision new content
		//
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_CONNECTION;

		data_size = sizeof(data32);
		spdm_get_data(spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO,
			      &parameter, &data32, &data_size);
		m_use_measurement_hash_algo = data32;
		data_size = sizeof(data32);
		spdm_get_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO,
			      &parameter, &data32, &data_size);
		m_use_asym_algo = data32;
		data_size = sizeof(data32);
		spdm_get_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO,
			      &parameter, &data32, &data_size);
		m_use_hash_algo = data32;
		data_size = sizeof(data16);
		spdm_get_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG,
			      &parameter, &data16, &data_size);
		m_use_req_asym_algo = data16;

		res = read_responder_public_certificate_chain(m_use_hash_algo,
							      m_use_asym_algo,
							      &data, &data_size,
							      NULL, NULL);
		if (res) {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			data8 = m_use_slot_count;
			spdm_set_data(spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT,
				      &parameter, &data8, sizeof(data8));

			for (index = 0; index < m_use_slot_count; index++) {
				parameter.additional_data[0] = index;
				spdm_set_data(spdm_context,
					      SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
					      &parameter, data, data_size);
			}
			// do not free it
		}

		if ((m_use_slot_id == 0xFF) ||
		    ((m_use_responder_capability_flags &
		      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) !=
		     0)) {
			res = read_requester_public_certificate_chain(
				m_use_hash_algo, m_use_req_asym_algo, &data,
				&data_size, NULL, NULL);
			if (res) {
				zero_mem(&parameter, sizeof(parameter));
				parameter.location = SPDM_DATA_LOCATION_LOCAL;
				spdm_set_data(spdm_context,
					      SPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
					      &parameter, data, data_size);
				// Do not free it.
			}
		} else {
			res = read_requester_root_public_certificate(
				m_use_hash_algo, m_use_req_asym_algo, &data,
				&data_size, &hash, &hash_size);
			x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
				data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
				&root_cert, &root_cert_size);
			if (res) {
				zero_mem(&parameter, sizeof(parameter));
				parameter.location = SPDM_DATA_LOCATION_LOCAL;
				spdm_set_data(
					spdm_context,
					SPDM_DATA_PEER_PUBLIC_ROOT_CERT,
					&parameter, root_cert, root_cert_size);
				// Do not free it.
			}
		}

		if (res) {
			data8 = m_use_mut_auth;
			parameter.additional_data[0] =
				m_use_slot_id; // req_slot_id;
			spdm_set_data(spdm_context,
				      SPDM_DATA_MUT_AUTH_REQUESTED, &parameter,
				      &data8, sizeof(data8));

			data8 = m_use_basic_mut_auth;
			parameter.additional_data[0] =
				m_use_slot_id; // req_slot_id;
			spdm_set_data(spdm_context,
				      SPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
				      &parameter, &data8, sizeof(data8));
		}

		status = spdm_set_data(spdm_context, SPDM_DATA_PSK_HINT, NULL,
				       TEST_PSK_HINT_STRING,
				       sizeof(TEST_PSK_HINT_STRING));
		if (RETURN_ERROR(status)) {
			printf("spdm_set_data - %x\n", (uint32)status);
		}

		if (m_save_state_file_name != NULL) {
			spdm_save_negotiated_state(spdm_context, FALSE);
		}

		break;

	default:
		break;
	}

	return;
}

/**
  Notify the session state to a session APP.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The session_id of a session.
  @param  session_state                 The state of a session.
**/
void spdm_server_session_state_callback(IN void *spdm_context,
					IN uint32 session_id,
					IN spdm_session_state_t session_state)
{
	uintn data_size;
	spdm_data_parameter_t parameter;
	uint8 data8;

	switch (session_state) {
	case SPDM_SESSION_STATE_NOT_STARTED:
		// Session end

		if (m_save_state_file_name != NULL) {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_SESSION;
			*(uint32 *)parameter.additional_data = session_id;

			data_size = sizeof(data8);
			spdm_get_data(spdm_context,
				      SPDM_DATA_SESSION_END_SESSION_ATTRIBUTES,
				      &parameter, &data8, &data_size);
			if ((data8 &
			     SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR) !=
			    0) {
				// clear
				spdm_clear_negotiated_state(spdm_context);
			} else {
				// preserve - already done in SPDM_CONNECTION_STATE_NEGOTIATED.
				// spdm_save_negotiated_state (spdm_context, FALSE);
			}
		}
		break;

	case SPDM_SESSION_STATE_HANDSHAKING:
		// no action
		break;

	case SPDM_SESSION_STATE_ESTABLISHED:
		// no action
		break;

	default:
		ASSERT(FALSE);
		break;
	}
}
