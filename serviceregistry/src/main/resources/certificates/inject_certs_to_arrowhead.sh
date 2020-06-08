#!/bin/bash

# Passwords
KEY_STORE_PWD=coapKey
TRUST_STORE_PWD=coapTrust

# Stores
KEY_STORE=coapKeyStore.p12
TRUST_STORE=coapTrustStore.p12

# Certs
ROOT_CER=coap-root.cer
CA_CER=coap-ca.cer

# Aliases
ALIAS_ROOT=coap-root
ALIAS_CA=coap-ca

# Configuration
VALIDITY=365 # days
CN_ROOT=arrowhead.eu

if [[ "$#" -ne 4 ]]; then
  echo "Incorrect usage!!"
  echo "Usage './script.sh trustStoreFile trustStorePassword keyStoreFile keyStorePassword'"
  exit 1
fi

# VARS
TRUST_STORE_ORIGINAL=$1
TRUST_STORE_ORIGINAL_PWD=$2
KEY_STORE_ORIGINAL=$3
KEY_STORE_ORIGINAL_PWD=$4

# Checking mandatory files
if [ ! -f $TRUST_STORE ]; then
  echo "$TRUST_STORE does not exist"
  exit 1
fi
if [ ! -f $ROOT_CER ]; then
  echo "$ROOT_CER does not exist"
  exit 1
fi
if [ ! -f $CA_CER ]; then
  echo "$CA_CER does not exist"
  exit 1
fi

# Copy files to keep originals
TRUST_STORE_CP="${TRUST_STORE_ORIGINAL%.*}-coap.""${TRUST_STORE_ORIGINAL##*.}"
KEY_STORE_CP="${KEY_STORE_ORIGINAL%.*}-coap.""${KEY_STORE_ORIGINAL##*.}"
cp $TRUST_STORE_ORIGINAL $TRUST_STORE_CP
cp $KEY_STORE_ORIGINAL $KEY_STORE_CP
rm -f $KEY_STORE

echo "Introduce Company:"
read COMPANY
echo "Introduce Cloud:"
read CLOUD

# Select Client or Service
SYSTEM="system"
SYSTEM_CER=$SYSTEM".cer"

echo "Introduce Server/Client name:"
read SYSTEM
SYSTEM=$SYSTEM"-coap"
SYSTEM_CER=$SYSTEM".cer"
echo "Creating SERVICE key ["$SYSTEM"] and certificate ["$SYSTEM_CER"]"
keytool -genkeypair -alias $SYSTEM -keyalg EC -dname 'CN='$SYSTEM'.'$CLOUD'.'$COMPANY'.'$CN_ROOT -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias $SYSTEM | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $ALIAS_CA -gencert -ext KU=dig -validity $VALIDITY -rfc >$SYSTEM_CER
keytool -alias $SYSTEM -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SYSTEM_CER -noprompt

# Inject System cert
keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias $SYSTEM -destkeystore $KEY_STORE_CP -deststorepass $KEY_STORE_ORIGINAL_PWD

# Inject ROOT and CA
echo "Injecting ROOT and CA certs"
keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias $ALIAS_ROOT -destkeystore $TRUST_STORE_CP -deststorepass $TRUST_STORE_ORIGINAL_PWD
keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias $ALIAS_CA -destkeystore $TRUST_STORE_CP -deststorepass $TRUST_STORE_ORIGINAL_PWD
#keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD   -alias $CLOUD_ALIAS      -destkeystore $CLOUD_KEY_STORE_P12       -deststorepass $KEY_STORE_PWD   -deststoretype PKCS12
#keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD   -alias $MASTER_ALIAS      -destkeystore $CLOUD_KEY_STORE_P12       -deststorepass $KEY_STORE_PWD   -deststoretype PKCS12
