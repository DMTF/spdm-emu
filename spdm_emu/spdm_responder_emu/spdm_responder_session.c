/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_emu.h"

spdm_vendor_defined_response_mine_t m_vendor_defined_response = {
	{
		SPDM_MESSAGE_VERSION_10, SPDM_VENDOR_DEFINED_RESPONSE,
		0, // param1
		0, // param2
	},
	SPDM_REGISTRY_ID_PCISIG, // standard_id
	2, // len
	SPDM_VENDOR_ID_PCISIG, // vendor_id
	sizeof(pci_protocol_header_t) +
		sizeof(pci_ide_km_query_resp_t), // payload_length
	{
		PCI_PROTOCAL_ID_IDE_KM,
	},
	{
		{
			PCI_IDE_KM_OBJECT_ID_QUERY_RESP,
		},
		0, // reserved
		0, // port_index
		0, // dev_func_num
		0, // bus_num
		0, // segment
		7, // max_port_index
	}
};

secure_session_response_mine_t m_secure_session_response = {
	{ MCTP_MESSAGE_TYPE_PLDM },
	{
		0,
		PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
		PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
	},
	{
		PLDM_BASE_CODE_SUCCESS,
	},
	1, // tid
};

/**
  Process a packet in the current SPDM session.

  @param  This                         Indicates a pointer to the calling context.
  @param  session_id                    ID of the session.
  @param  request                      A pointer to the request data.
  @param  request_size                  size of the request data.
  @param  response                     A pointer to the response data.
  @param  response_size                 size of the response data. On input, it means the size of data
                                       buffer. On output, it means the size of copied data buffer if
                                       RETURN_SUCCESS, and means the size of desired data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM request is set successfully.
  @retval RETURN_INVALID_PARAMETER        The data_size is NULL or the data is NULL and *data_size is not zero.
  @retval RETURN_UNSUPPORTED              The data_type is unsupported.
  @retval RETURN_NOT_FOUND                The data_type cannot be found.
  @retval RETURN_NOT_READY                The data_type is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/
return_status test_spdm_process_packet_callback(
	IN uint32_t *session_id, IN boolean is_app_message, IN void *request,
	IN uintn request_size, OUT void *response, IN OUT uintn *response_size)
{
	spdm_vendor_defined_request_mine_t *spdm_request;
	secure_session_request_mine_t *app_request;

	if (!is_app_message) {
		spdm_request = request;
		ASSERT((request_size >=
			sizeof(spdm_vendor_defined_request_mine_t)) &&
		       (request_size <
			sizeof(spdm_vendor_defined_request_mine_t) + 4));
		ASSERT(spdm_request->header.request_response_code ==
		       SPDM_VENDOR_DEFINED_REQUEST);
		ASSERT(spdm_request->standard_id == SPDM_REGISTRY_ID_PCISIG);
		ASSERT(spdm_request->vendor_id == SPDM_VENDOR_ID_PCISIG);
		ASSERT(spdm_request->payload_length ==
		       sizeof(pci_protocol_header_t) +
			       sizeof(pci_ide_km_query_t));
		ASSERT(spdm_request->pci_protocol.protocol_id ==
		       PCI_PROTOCAL_ID_IDE_KM);
		ASSERT(spdm_request->pci_ide_km_query.header.object_id ==
		       PCI_IDE_KM_OBJECT_ID_QUERY);

		copy_mem(response, &m_vendor_defined_response,
			 sizeof(m_vendor_defined_response));
		*response_size = sizeof(m_vendor_defined_response);
	} else {
		app_request = request;
		ASSERT(request_size == sizeof(secure_session_request_mine_t));
		ASSERT(app_request->mctp_header.message_type ==
		       MCTP_MESSAGE_TYPE_PLDM);
		ASSERT(app_request->pldm_header.pldm_type ==
		       PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
		ASSERT(app_request->pldm_header.pldm_command_code ==
		       PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);

		copy_mem(response, &m_secure_session_response,
			 sizeof(m_secure_session_response));
		*response_size = sizeof(m_secure_session_response);
	}

	return RETURN_SUCCESS;
}

return_status spdm_get_response_vendor_defined_request(
	IN void *spdm_context, IN uint32_t *session_id, IN boolean is_app_message,
	IN uintn request_size, IN void *request, IN OUT uintn *response_size,
	OUT void *response)
{
	return_status status;

	status = test_spdm_process_packet_callback(session_id, is_app_message,
						   request, request_size,
						   response, response_size);
	if (RETURN_ERROR(status)) {
		libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
	}
	return RETURN_SUCCESS;
}
