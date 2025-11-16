#!/bin/sh -e

SWTPM_STATE_DIR="$(mktemp -d /tmp/swtpm-state.XXXXXXXXXX)"

mkdir -p "${SWTPM_STATE_DIR}"

while [ $# -gt 0 ] ; do
    case "$1" in
        --start-swtpm)
            START_SWTPM=1
            ;;
        --wait-swtpm)
            WAIT_SWTPM=1
            ;;
        --cleanup)
            CLEANUP=1
            ;;
    esac
    shift
done

cat > openssl.cnf << EOF
[v3_ca]
basicConstraints = critical,CA:true

[ v3_req ]
basicConstraints = critical,CA:false
EOF

if [ -n "$START_SWTPM" ] ; then
    swtpm_setup --tpm2 --create-config-files overwrite,root
    
    swtpm_setup --tpm2 --config ~/.config/swtpm_setup.conf \
        --tpm-state ${SWTPM_STATE_DIR} \
        --overwrite --create-ek-cert \
        --create-platform-cert \
        --write-ek-cert-files ${SWTPM_STATE_DIR}

    echo "Starting SWTPM"
    swtpm socket \
        --tpmstate dir="${SWTPM_STATE_DIR}" \
        --tpm2 \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322 \
        --flags not-need-init,startup-clear &
    SWTPM_PID="$!"

    cleanup() {
        if [ ! -z "$CLEANUP_DONE" ] ; then
            exit 1
        fi

        CLEANUP_DONE=1
        echo "Killing swtpm ${SWTPM_PID}..."
        kill -9 ${SWTPM_PID}

        echo "Cleaning up cache"
        rm -rf "${SWTPM_STATE_DIR}"
        exit 1
    }

    trap cleanup EXIT INT

    sleep 1
fi

# export TPM2TOOLS_TCTI="swtpm:port=2321"

echo "Checking tpm availability...."
tpm2_getcap properties-fixed || {
    echo "tpm2_getcap failed"
    exit 1
}

if [ -n "$CLEANUP" ] ; then
    echo "Cleaning up pesistent handles"
    tpm2_evictcontrol -C o -c 0x81000001 || true
    tpm2_evictcontrol -C o -c 0x81000002 || true
    tpm2_evictcontrol -C o -c 0x81000003 || true
    tpm2_nvundefine -C o 0x1500021       || true
    tpm2_nvundefine -C o 0x1500022       || true
    tpm2_nvundefine -C o 0x1500023       || true
    tpm2_flushcontext --transient-object
fi

echo "Flushing any pre-existing transient/session handles..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true


#
# Root CA
#

echo "Creating root ca context..."
tpm2_createprimary -C e -g sha256 -G ecc -c root_ca.ctx

echo "Creating root keys..."
tpm2_create -C root_ca.ctx -G ecc -u root_ca.pub -r root_ca.priv

echo "Loading root key..."
tpm2_load -C root_ca.ctx -u root_ca.pub -r root_ca.priv -c root_ca_key.ctx

echo "Persisting root ca at 0x8010001..."
tpm2_evictcontrol -C o -c root_ca_key.ctx 0x81000001
tpm2_flushcontext --transient-object

echo "Generating root ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Root CA" \
    -key "handle:0x81000001" \
    -config openssl.cnf \
    -extensions v3_ca \
    -out root_ca_cert.csr

echo "Generatng root ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in root_ca_cert.csr \
    -signkey "handle:0x81000001" \
    -extfile openssl.cnf \
    -extensions v3_ca \
    -days 356 \
    -out root_ca_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in root_ca_cert.pem \
    -out root_ca_cert.der

echo "Storing root ca into TPM NVram"
tpm2_nvdefine 0x1500021 -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite 0x1500021 -C o -i root_ca_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object || true

#
# Requester
#

echo "Creating requester ca context..."
tpm2_createprimary -C e -g sha256 -G ecc -c requester.ctx

echo "Creating requester keys..."
tpm2_create -C requester.ctx -G ecc -u requester.pub -r requester.priv

echo "Loading requester key..."
tpm2_load -C requester.ctx -u requester.pub -r requester.priv -c requester_key.ctx

echo "Persisting requester ca at 0x8010001..."
tpm2_evictcontrol -C o -c requester_key.ctx 0x81000002
tpm2_flushcontext --transient-object

echo "Generating requester ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Requester Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:0x81000002" \
    -out requester_cert.csr

echo "Generatng requester ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in requester_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:0x81000001" \
    -days 356 \
    -extfile openssl.cnf \
    -extensions v3_req \
    -out requester_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in requester_cert.pem \
    -out requester_cert.der

echo "Creating certificate chain..."
cat root_ca_cert.der requester_cert.der > requester_certchain.der

# echo "Converting pem certchain to der..."
# openssl x509 \
#     -outform DER \
#     -in requester_certchain.pem \
#     -out requester_certchain.der

echo "Storing requester ca into TPM NVram"
tpm2_nvdefine 0x1500022 -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite 0x1500022 -C o -i requester_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object || true

#
# Responder
#

echo "Creating responder ca context..."
tpm2_createprimary -C e -g sha256 -G ecc -c responder.ctx

echo "Creating responder keys..."
tpm2_create -C responder.ctx -G ecc -u responder.pub -r responder.priv

echo "Loading responder key..."
tpm2_load -C responder.ctx -u responder.pub -r responder.priv -c responder_key.ctx

echo "Persisting responder ca at 0x8010001..."
tpm2_evictcontrol -C o -c responder_key.ctx 0x81000003
tpm2_flushcontext --transient-object

echo "Generating responder ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Responder Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:0x81000003" \
    -out responder_cert.csr

echo "Generatng responder ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in responder_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:0x81000001" \
    -extfile openssl.cnf \
    -extensions v3_req \
    -days 356 \
    -out responder_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in responder_cert.pem \
    -out responder_cert.der

echo "Creating certificate chain..."
cat root_ca_cert.der responder_cert.der > responder_certchain.der

# echo "Converting pem certchain to der..."
# openssl x509 \
#     -outform DER \
#     -in responder_certchain.pem \
#     -out responder_certchain.der

echo "Storing responder ca into TPM NVram"
tpm2_nvdefine 0x1500023 -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite 0x1500023 -C o -i responder_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object || true

if [ -n "$START_SWTPM" ] ; then
    echo "Run following command before using SWTPM via tpm2-tools"
    echo "  $ export TMP2TOOLS_TCTI=swtpm:port=2321"

    if [ -n "$WAIT_SWTPM" ] ; then
        echo "Press CTRL+C to stop swtpm"
        wait $SWTPM_PID
    fi
fi
