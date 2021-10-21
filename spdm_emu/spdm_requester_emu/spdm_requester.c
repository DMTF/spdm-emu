/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_requester_emu.h"

void *m_spdm_context;
SOCKET m_socket;

boolean communicate_platform_data(IN SOCKET socket, IN uint32 command,
				  IN uint8 *send_buffer, IN uintn bytes_to_send,
				  OUT uint32 *response,
				  IN OUT uintn *bytes_to_receive,
				  OUT uint8 *receive_buffer)
{
	boolean result;

	result =
		send_platform_data(socket, command, send_buffer, bytes_to_send);
	if (!result) {
		printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return result;
	}

	result = receive_platform_data(socket, response, receive_buffer,
				       bytes_to_receive);
	if (!result) {
		printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
		       WSAGetLastError()
#else
		       errno
#endif
		);
		return result;
	}
	return result;
}

return_status spdm_device_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64 timeout)
{
	boolean result;

	result = send_platform_data(m_socket, SOCKET_SPDM_COMMAND_NORMAL,
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
	uint32 command;

	result = receive_platform_data(m_socket, &command, response,
				       response_size);
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
	return RETURN_SUCCESS;
}

void *spdm_client_init(void)
{
	void *spdm_context;
	uint8 index;
	return_status status;
	boolean res;
	void *data;
	uintn data_size;
	spdm_data_parameter_t parameter;
	uint8 data8;
	uint16 data16;
	uint32 data32;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
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
		spdm_load_negotiated_state(spdm_context, TRUE);
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
	data32 = m_use_requester_capability_flags;
	if (m_use_capability_flags != 0) {
		data32 = m_use_capability_flags;
	}
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter,
		      &data32, sizeof(data32));

	data8 = m_support_measurement_spec;
	spdm_set_data(spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter,
		      &data8, sizeof(data8));
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

	if (m_load_state_file_name == NULL) {
		// Skip if state is loaded
		status = spdm_init_connection(
			spdm_context,
			(m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0);
		if (RETURN_ERROR(status)) {
			printf("spdm_init_connection - 0x%x\n", (uint32)status);
			free(m_spdm_context);
			m_spdm_context = NULL;
			return NULL;
		}
	}

	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_CONNECTION;

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_CONNECTION_STATE, &parameter,
		      &data32, &data_size);
	ASSERT(data32 == SPDM_CONNECTION_STATE_NEGOTIATED);

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_measurement_hash_algo = data32;
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, &data_size);
	m_use_asym_algo = data32;
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_hash_algo = data32;
	data_size = sizeof(data16);
	spdm_get_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, &data_size);
	m_use_req_asym_algo = data16;

	if ((m_use_slot_id == 0xFF) ||
	    ((m_use_requester_capability_flags &
	      SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0)) {
		res = read_responder_public_certificate_chain(m_use_hash_algo,
							      m_use_asym_algo,
							      &data, &data_size,
							      NULL, NULL);
		if (res) {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_set_data(spdm_context,
				      SPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
				      &parameter, data, data_size);
			// Do not free it.
		} else {
			printf("read_responder_public_certificate_chain fail!\n");
			free(m_spdm_context);
			m_spdm_context = NULL;
			return NULL;
		}
	} else {
		res = read_responder_root_public_certificate(m_use_hash_algo,
							     m_use_asym_algo,
							     &data, &data_size,
							     &hash, &hash_size);
		x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
			data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
			&root_cert, &root_cert_size);
		if (res) {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_set_data(spdm_context,
				      SPDM_DATA_PEER_PUBLIC_ROOT_CERT,
				      &parameter, root_cert, root_cert_size);
			// Do not free it.
		} else {
			printf("read_responder_root_public_certificate fail!\n");
			free(m_spdm_context);
			m_spdm_context = NULL;
			return NULL;
		}
	}

	res = read_requester_public_certificate_chain(m_use_hash_algo,
						      m_use_req_asym_algo,
						      &data, &data_size, NULL,
						      NULL);
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
	} else {
		printf("read_requester_public_certificate_chain fail!\n");
		free(m_spdm_context);
		m_spdm_context = NULL;
		return NULL;
	}

	status = spdm_set_data(spdm_context, SPDM_DATA_PSK_HINT, NULL,
			       TEST_PSK_HINT_STRING,
			       sizeof(TEST_PSK_HINT_STRING));
	if (RETURN_ERROR(status)) {
		printf("spdm_set_data - %x\n", (uint32)status);
	}

	if (m_save_state_file_name != NULL) {
		spdm_save_negotiated_state(spdm_context, TRUE);
	}

	return m_spdm_context;
}
