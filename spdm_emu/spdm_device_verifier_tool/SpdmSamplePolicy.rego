# OPA playground: https://play.openpolicyagent.org/

package spdm

default SPDM_HASH_CHECK1 = false
SPDM_HASH_CHECK1 {
    input.reference.corim.signed_corim.cose_sign1[2].corim.unsigned_corim_map.corim_tags[0].comid_triples.comid_reference_triples[0][1].comid_mval.comid_digests[0][1] == input.evidence.evidences[0].evidence.digest[1]
}

SPDM_SVN_CHECK1 {
    input.reference.corim.signed_corim.cose_sign1[2].corim.unsigned_corim_map.corim_tags[0].comid_triples.comid_reference_triples[4][1].comid_mval.comid_svn == input.evidence.evidences[4].evidence.svn
}

default error_code = 1
error_code = 0 { 
    SPDM_HASH_CHECK1
    SPDM_SVN_CHECK1
}

# Output: error code, hash check
output := {
    "error_code": error_code,
    "SPDM_HASH_CHECK": SPDM_HASH_CHECK1,
    "SPDM_SVN_CHECK": SPDM_SVN_CHECK1,
}
