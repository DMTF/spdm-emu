# OPA playground: https://play.openpolicyagent.org/

package spdm

evidence_arr := input.evidence.evidences

reference_arr := input.reference.corim.unsigned_corim_map.corim_tags[0].comid_triples.comid_reference_triples

ev_hash_list[hash] {
    evidence := evidence_arr[_]
    digest := evidence.evidence.digest
    hash := digest[1]
}

ev_svn[svn] {
	evidence := evidence_arr[_]
    svn := evidence.evidence.svn
}

ref_hash_list[hash] {
    references := reference_arr[_]
    reference := references[_]
    hashes := reference.comid_mval.comid_digests[0]
    hash := hashes[1]
}

ref_svn[svn] {
    references := reference_arr[_]
    reference := references[_]
    svn := reference.comid_mval.comid_svn
}

default SPDM_HASH_CHECK = false
SPDM_HASH_CHECK {
    ev_hash_list == ref_hash_list
}

default SPDM_SVN_CHECK = false
SPDM_SVN_CHECK {
    ev_svn == ref_svn
}

default error_code = 1
error_code = 0 { 
    SPDM_HASH_CHECK
    SPDM_SVN_CHECK
}

# Output: error code, hash check, svn check
output := {
    "error_code": error_code,
    "SPDM_HASH_CHECK": SPDM_HASH_CHECK,
    "SPDM_SVN_CHECK": SPDM_SVN_CHECK,
}