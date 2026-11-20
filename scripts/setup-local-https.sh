#!/usr/bin/env bash
# Generate an IP certificate on the Ubuntu server. No DNS or system trust changes.
set -euo pipefail
umask 077

SERVER_IP="${1:-192.168.99.82}"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${TLS_CERT_DIR:-$PROJECT_DIR/certs}"
command -v openssl >/dev/null || { echo 'Install OpenSSL first: sudo apt install openssl' >&2; exit 1; }
if [[ ! "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo 'Provide an IPv4 address, for example 192.168.99.82.' >&2
    exit 1
fi
IFS=. read -r ip_a ip_b ip_c ip_d <<< "$SERVER_IP"
for octet in "$ip_a" "$ip_b" "$ip_c" "$ip_d"; do
    if (( 10#$octet > 255 )); then echo 'Invalid IPv4 address.' >&2; exit 1; fi
done
mkdir -p -- "$CERT_DIR"
chmod 700 "$CERT_DIR"
WORK_DIR="$(mktemp -d "$CERT_DIR/.https.XXXXXX")"
trap 'rm -f -- "$WORK_DIR/ca.key" "$WORK_DIR/ca.crt" "$WORK_DIR/server.key" "$WORK_DIR/server.csr" "$WORK_DIR/server.crt" "$WORK_DIR/extensions.cnf"; rmdir -- "$WORK_DIR"' EXIT

if [[ -e "$CERT_DIR/portal-root-ca.key" || -e "$CERT_DIR/portal-root-ca.crt" ]]; then
    if [[ ! -f "$CERT_DIR/portal-root-ca.key" || ! -f "$CERT_DIR/portal-root-ca.crt" ]]; then
        echo 'CA key/certificate pair is incomplete. Restore the missing file; do not replace a trusted CA.' >&2
        exit 1
    fi
    openssl x509 -in "$CERT_DIR/portal-root-ca.crt" -checkend 86400 -noout
else
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -keyout "$WORK_DIR/ca.key" -out "$WORK_DIR/ca.crt" \
        -subj '/CN=Infrastructure Portal Local CA' \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -addext 'subjectKeyIdentifier=hash'
    mv -- "$WORK_DIR/ca.key" "$CERT_DIR/portal-root-ca.key"
    mv -- "$WORK_DIR/ca.crt" "$CERT_DIR/portal-root-ca.crt"
fi

if [[ ! -f "$CERT_DIR/server.key" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/server.key"
    mv -- "$WORK_DIR/server.key" "$CERT_DIR/server.key"
fi
openssl req -new -key "$CERT_DIR/server.key" -out "$WORK_DIR/server.csr" -subj "/CN=$SERVER_IP"
cat > "$WORK_DIR/extensions.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$SERVER_IP
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$WORK_DIR/server.csr" \
    -CA "$CERT_DIR/portal-root-ca.crt" -CAkey "$CERT_DIR/portal-root-ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days 365 \
    -extfile "$WORK_DIR/extensions.cnf" -out "$WORK_DIR/server.crt"
openssl verify -CAfile "$CERT_DIR/portal-root-ca.crt" -verify_ip "$SERVER_IP" "$WORK_DIR/server.crt"
mv -- "$WORK_DIR/server.crt" "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.key" "$CERT_DIR/portal-root-ca.key"
chmod 644 "$CERT_DIR/server.crt" "$CERT_DIR/portal-root-ca.crt"
printf '\nHTTPS certificate ready for https://%s\n' "$SERVER_IP"
printf 'Install this PUBLIC CA certificate on the phones: %s/portal-root-ca.crt\n' "$CERT_DIR"
printf 'Keep all .key files on the server. Back up the CA pair for future renewals.\n'
openssl x509 -in "$CERT_DIR/portal-root-ca.crt" -noout -fingerprint -sha256
printf '\nStart HTTPS from the project directory:\n'
printf '  docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build\n'
