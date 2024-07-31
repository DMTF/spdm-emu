# spdm_emu Tool

This document describes spdm_requester_emu and spdm_responder_emu tool. It can be used to test the SPDM communication in the OS.

## Spdm OS tool user guide

   ```
      spdm_requester_emu|spdm_responder_emu [--trans MCTP|PCI_DOE]
         [--ver 1.0|1.1|1.2|1.3]
         [--sec_ver 1.0|1.1|1.2]
         [--cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID|CHUNK|ALIAS_CERT|SET_CERT|CSR|CERT_INSTALL_RESET|EP_INFO_NO_SIG|EP_INFO_SIG|MEL|EVENT|MULTI_KEY_ONLY|MULTI_KEY_NEG|GET_KEY_PAIR_INFO|SET_KEY_PAIR_INFO]
         [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512|SM3_256]
         [--meas_spec DMTF]
         [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512|SM3_256]
         [--mel_spec DMTF]
         [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521|SM2_P256|EDDSA_25519|EDDSA_448]
         [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521|SM2_P256|EDDSA_25519|EDDSA_448]
         [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1|SM2_P256]
         [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305|SM4_128_GCM]
         [--key_schedule HMAC_HASH]
         [--other_param OPAQUE_FMT_1|MULTI_KEY_CONN]
         [--peer_cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID|CHUNK|ALIAS_CERT|SET_CERT|CSR|CERT_INSTALL_RESET|EP_INFO_NO_SIG|EP_INFO_SIG|MEL|EVENT|MULTI_KEY_ONLY|MULTI_KEY_NEG|GET_KEY_PAIR_INFO|SET_KEY_PAIR_INFO]
         [--basic_mut_auth NO|BASIC]
         [--mut_auth NO|WO_ENCAP|W_ENCAP|DIGESTS]
         [--meas_sum NO|TCB|ALL]
         [--meas_op ONE_BY_ONE|ALL]
         [--meas_att HASH|RAW]
         [--key_upd REQ|ALL|RSP]
         [--slot_id <0~7|0xFF>]
         [--slot_count <1~8>]
         [--save_state <NegotiateStateFileName>]
         [--load_state <NegotiateStateFileName>]
         [--exe_mode SHUTDOWN|CONTINUE]
         [--exe_conn VER_ONLY|DIGEST|CERT|CHAL|MEAS|MEL|GET_CSR|SET_CERT|GET_KEY_PAIR_INFO]
         [--exe_session KEY_EX|PSK|NO_END|KEY_UPDATE|HEARTBEAT|MEAS|DIGEST|CERT|GET_CSR|SET_CERT|APP]
         [--pcap <PcapFileName>]
         [--priv_key_mode PEM|RAW]

      NOTE:
         [--trans] is used to select transport layer message. By default, MCTP is used.
         [--ver] is version. By default, all are used.
         [--sec_ver] is secured message version. By default, all are used.
         [--cap] is capability flags. Multiple flags can be set together. Please use ',' for them.
                 By default, CERT,CHAL,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,MULTI_KEY_NEG is used for Requester.
                 By default, CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK_WITH_CONTEXT,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,SET_CERT,CSR,MULTI_KEY_NEG,GET_KEY_PAIR_INFO is used for Responder.
         [--hash] is hash algorithm. By default, SHA_384,SHA_256 is used.
         [--meas_spec] is measurement hash spec. By default, DMTF is used.
         [--meas_hash] is measurement hash algorithm. By default, SHA_512,SHA_384,SHA_256 is used.
         [--mel_spec] is MEL spec. By default, DMTF is used.
         [--asym] is asym algorithm. By default, ECDSA_P384,ECDSA_P256 is used.
         [--req_asym] is requester asym algorithm. By default, RSAPSS_3072,RSAPSS_2048,RSASSA_3072,RSASSA_2048 is used.
         [--dhe] is DHE algorithm. By default, SECP_384_R1,SECP_256_R1,FFDHE_3072,FFDHE_2048 is used.
         [--aead] is AEAD algorithm. By default, AES_256_GCM,CHACHA20_POLY1305 is used.
         [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.
         [--other_param] is other parameter support. By default, OPAQUE_FMT_1,MULTI_KEY_CONN is used.
                 Above algorithms also support multiple flags. Please use ',' for them.
                 Not all the algorithms are supported, especially SHA3, EDDSA, and SMx.
                 Please don't mix NIST algo with SMx algo.
         [--peer_cap] is capability flags for the peer. It is used only when --exe_conn has VER_ONLY.
         [--basic_mut_auth] is the basic mutual authentication policy. BASIC is used in CHALLENGE_AUTH. By default, BASIC is used.
         [--mut_auth] is the mutual authentication policy. WO_ENCAP, W_ENCAP or DIGESTS is used in KEY_EXCHANGE_RSP. By default, W_ENCAP is used.
         [--meas_sum] is the measurment summary hash type in CHALLENGE_AUTH, KEY_EXCHANGE_RSP and PSK_EXCHANGE_RSP. By default, ALL is used.
         [--meas_op] is the measurement operation in GET_MEASUREMEMT. By default, ONE_BY_ONE is used.
         [--meas_att] is the measurement attribute in GET_MEASUREMEMT. By default, HASH is used.
         [--key_upd] is the key update operation in KEY_UPDATE. By default, ALL is used. RSP will trigger encapsulated KEY_UPDATE.
         [--slot_id] is to select the peer slot ID in GET_MEASUREMENT, CHALLENGE_AUTH, KEY_EXCHANGE and FINISH. By default, 0 is used.
                 0xFF can be used to indicate provisioned certificate chain. No GET_CERTIFICATE is needed.
         [--slot_count] is to select the local slot count. By default, 3 is used. And the slot store cert chain continuously in emu.
         [--save_state] is to save the current negotiated state to a write-only file.
                 The requester and responder will save state after GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.
                 (negotiated state == ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule|other_param)
                 The responder should set CACHE capabilities, otherwise the state will not be saved.
                 The requester will clear PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION to preserve, otherwise this bit is set.
                 The responder will save empty state, if the requester sets PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION.
         [--load_state] is to load the negotiated state to current session from a read-only file.
                 The requester and responder will provision the state just after SPDM context is created.
                 The user need guarantee the state file is gnerated correctly.
                 The command line input - ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule|other_param are ignored.
                 The requester will skip GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.
         [--exe_mode] is used to control the execution mode. By default, it is SHUTDOWN.
                 SHUTDOWN means the requester asks the responder to stop.
                 CONTINUE means the requester asks the responder to preserve the current SPDM context.
         [--exe_conn] is used to control the SPDM connection. By default, it is DIGEST,CERT,CHAL,MEAS,MEL,GET_CSR,SET_CERT, GET_KEY_PAIR_INFO.
                 VER_ONLY means REQUESTER does not send GET_CAPABILITIES/NEGOTIATE_ALGORITHMS. It is used for quick symmetric authentication with PSK.
                     The version for responder must be provisioned from ver.
                     The capablities for local and peer are from cap|peer_cap.
                     The negotiated algorithms are from hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule|other_param and they shall have at most 1 bit set.
                 DIGEST means send GET_DIGESTS command.
                 CERT means send GET_CERTIFICATE command.
                 CHAL means send CHALLENGE command.
                 MEAS means send GET_MEASUREMENT command.
                 MEL means send GET_MEL command.
                 GET_CSR means send GET_CSR command.
                 SET_CERT means send SET_CERTIFICATE command.
                 GET_KEY_PAIR_INFO means send GET_KEY_PAIR_INFO command.
         [--exe_session] is used to control the SPDM session. By default, it is KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,MEL,DIGEST,CERT,GET_CSR,SET_CERT,GET_KEY_PAIR_INFO,APP.
                 KEY_EX means to setup KEY_EXCHANGE session.
                 PSK means to setup PSK_EXCHANGE session.
                 NO_END means to not send END_SESSION.
                 KEY_UPDATE means to send KEY_UPDATE in session.
                 HEARTBEAT means to send HEARTBEAT in session.
                 MEAS means send GET_MEASUREMENT command in session.
                 MEL means send GET_MEL command in session.
                 DIGEST means send GET_DIGESTS command in session.
                 CERT means send GET_CERTIFICATE command in session.
                 GET_CSR means send GET_CSR command in session.
                 SET_CERT means send SET_CERTIFICATE command in session.
                 GET_KEY_PAIR_INFO means send GET_KEY_PAIR_INFO command in session.
                 APP means send vendor defined message or application message in session.
         [--pcap] is used to generate PCAP dump file for offline analysis.
         [--priv_key_mode] is uesed to confirm private key mode with LIBSPDM_PRIVATE_KEY_USE_PEM.
   ```

   Take spdm_requester_emu or spdm_responder_emu as an example, a user may use `spdm_requester_emu --pcap SpdmRequester.pcap > SpdmRequester.log` or `spdm_responder_emu --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   To test PCI_DOE, a user may use `spdm_requester_emu --trans PCI_DOE --pcap SpdmRequester.pcap > SpdmRequester.log` or `spdm_responder_emu  --trans PCI_DOE --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   [spdm_dump](https://github.com/DMTF/spdm-dump/blob/main/doc/spdm_dump.md) tool can be used to parse the pcap file for offline analysis.

   NOTE: Not all combination is supported. Please file issue or submit patch for them if you find something is not expected.
