#!/bin/sh -e

SWTPM_STATE_DIR="$(mktemp -d /tmp/swtpm-state.XXXXXXXXXX)"
KEY_ALGORITHM=ecc
HASH_ALGORITHM=256

ROOT_CTX=0x81000000
ROOT_KEY=0x81000001
REQU_CTX=0x81000010
REQU_KEY=0x81000011
RESP_CTX=0x81000020
RESP_KEY=0x81000021

ROOT_CERT=0x1500000
REQU_CERT=0x1500010
RESP_CERT=0x1500020

REQU_CERT_CHAIN=0x1500011
RESP_CERT_CHAIN=0x1500021

mkdir -p "${SWTPM_STATE_DIR}"

while [ $# -gt 0 ] ; do
    case "$1" in
        --start-swtpm)
            START_SWTPM=1
            ;;
        --key-algorithm=*)
            KEY_ALGORITHM=${1#*=}
            ;;
        --hash-algorithm=*)
            HASH_ALGORITHM=${1#*=}
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
    
    echo "Starting SWTPM"
    swtpm socket \
        --tpm2 \
        --flags not-need-init,startup-clear \
        --tpmstate dir="${SWTPM_STATE_DIR}" \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322  &
    SWTPM_PID="$!"
    sleep 1

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

    if [ -n "$CLEANUP_DONE" ] ; then
        trap cleanup EXIT INT
        exit 1
    fi

    sleep 1
fi

echo "Checking tpm availability...."
tpm2_getcap properties-fixed || {
    echo "tpm2_getcap failed"
    exit 1
}

if [ -n "$CLEANUP" ] ; then
    echo "Cleaning up pesistent handles"
    for i in $ROOT_CTX $ROOT_KEY $REQU_CTX $REQU_KEY $RESP_CTX $RESP_KEY ; do
        tpm2_evictcontrol -C o -c "$i" || true
    done
    for i in $ROOT_CERT $REQU_CERT $RESP_CERT $REQU_CERT_CHAIN $RESP_CERT_CHAIN ; do
        tpm2_nvundefine -C o "$i" || true
    done
    tpm2_flushcontext --transient-object
fi

echo "Flushing any pre-existing transient/session handles..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Root CA
#

echo "Creating root ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c root_ca.ctx
tpm2_evictcontrol -C o -c root_ca.ctx ${ROOT_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating root keys..."
tpm2_create -C ${ROOT_CTX} -G ${KEY_ALGORITHM} -u root_ca.pub -r root_ca.priv

echo "Loading root key..."
tpm2_load -C ${ROOT_CTX} -u root_ca.pub -r root_ca.priv -c root_ca_key.ctx

echo "Persisting root ca at 0x8010001..."
tpm2_evictcontrol -C o -c root_ca_key.ctx ${ROOT_KEY}
tpm2_flushcontext --transient-object

echo "Generating root ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Root CA" \
    -key "handle:${ROOT_KEY}" \
    -config openssl.cnf \
    -extensions v3_ca \
    -out root_ca_cert.csr

echo "Generatng root ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in root_ca_cert.csr \
    -signkey "handle:${ROOT_KEY}" \
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
tpm2_nvdefine ${ROOT_CERT} -C o -s $(stat -c %s root_ca_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${ROOT_CERT} -C o -i root_ca_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Requester
#

echo "Creating requester ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c requester.ctx
tpm2_evictcontrol -C o -c requester.ctx ${REQU_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating requester keys..."
tpm2_create -C ${REQU_CTX} -G ${KEY_ALGORITHM} -u requester.pub -r requester.priv

echo "Loading requester key..."
tpm2_load -C ${REQU_CTX} -u requester.pub -r requester.priv -c requester_key.ctx

echo "Persisting requester ca at 0x8010001..."
tpm2_evictcontrol -C o -c requester_key.ctx ${REQU_KEY}
tpm2_flushcontext --transient-object

echo "Generating requester ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Requester Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:${REQU_KEY}" \
    -out requester_cert.csr

echo "Generatng requester ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in requester_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
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
#    -outform DER \
#    -in requester_certchain.pem \
#    -out requester_certchain.der

echo "Storing requester ca into TPM NVram"
tpm2_nvdefine ${REQU_CERT} -C o -s $(stat -c %s requester_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT} -C o -i requester_cert.der

echo "Storing requester ca chain into TPM NVram"
tpm2_nvdefine ${REQU_CERT_CHAIN} -C o -s $(stat -c %s requester_certchain.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT_CHAIN} -C o -i requester_certchain.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Responder
#

echo "Creating responder ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c responder.ctx
tpm2_evictcontrol -C o -c responder.ctx ${RESP_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating responder keys..."
tpm2_create -C ${RESP_CTX} -G ${KEY_ALGORITHM} -u responder.pub -r responder.priv

echo "Loading responder key..."
tpm2_load -C ${RESP_CTX} -u responder.pub -r responder.priv -c responder_key.ctx

echo "Persisting responder ca at 0x8010001..."
tpm2_evictcontrol -C o -c responder_key.ctx ${RESP_KEY}
tpm2_flushcontext --transient-object

echo "Generating responder ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Responder Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:${RESP_KEY}" \
    -out responder_cert.csr

echo "Generatng responder ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in responder_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
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
tpm2_nvdefine ${RESP_CERT} -C o -s $(stat -c %s responder_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT} -C o -i responder_cert.der

echo "Storing responder ca chain into TPM NVram"
tpm2_nvdefine ${RESP_CERT_CHAIN} -C o -s $(stat -c %s responder_certchain.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT_CHAIN} -C o -i responder_certchain.der

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

echo "Done"