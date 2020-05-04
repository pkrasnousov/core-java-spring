#!/bin/bash

# Passwords
KEY_STORE_PWD=coapKey
TRUST_STORE_PWD=coapTrust

# Stores
KEY_STORE=coapKeyStore.pk12
TRUST_STORE=coapTrustStore.pk12

# Certs
ROOT_CER=coap-root.cer
CA_CER=coap-ca.cer
SERVICE_CER=coap-service.cer
CLIENT_CER=coap-client.cer

# Aliases
ALIAS_ROOT=coap-root
ALIAS_CA=coap-ca
ALIAS_SERVICE=coap-service
ALIAS_CLIENT=coap-client

# Configuration
VALIDITY=365 #days
CN_ROOT=arrowhead.eu
CN_SERVICE=service.arrowhead.eu
CN_CLIENT=client.arrowhead.eu

remove_files() {
  echo "Removing old files"
  rm -f $KEY_STORE $TRUST_STORE
  rm -f $ROOT_CER $CA_CER $SERVICE_CER $CLIENT_CER
}

create_keys() {
  echo "Creating keys"

  echo "Creating ROOT key ["$ALIAS_ROOT"] and certificate ["$ROOT_CER"]"
  keytool -genkeypair -alias $ALIAS_ROOT -keyalg EC -dname 'CN='$CN_ROOT -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias $ALIAS_ROOT | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $ALIAS_ROOT -gencert -validity $VALIDITY -ext BC=ca:true -rfc >$ROOT_CER
  keytool -alias $ALIAS_ROOT -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $ROOT_CER

  echo "Creating CA key ["$ALIAS_CA"] and certificate ["$CA_CER"]"
  keytool -genkeypair -alias $ALIAS_CA -keyalg EC -dname 'CN='$CN_ROOT -ext BC=1 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias $ALIAS_CA | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $ALIAS_ROOT -gencert -validity $VALIDITY -ext BC=1 -ext KU=keyCertSign,cRLSign -rfc >$CA_CER
  keytool -alias $ALIAS_CA -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_CER

  echo "Creating SERVICE key ["$ALIAS_SERVICE"] and certificate ["$SERVICE_CER"]"
  keytool -genkeypair -alias $ALIAS_SERVICE -keyalg EC -dname 'CN='$CN_SERVICE -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
  keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias $ALIAS_SERVICE | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $ALIAS_CA -gencert -ext KU=dig -validity $VALIDITY -rfc >$SERVICE_CER
  keytool -alias $ALIAS_SERVICE -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVICE_CER -noprompt

  echo "Creating CLIENT key ["$ALIAS_CLIENT"] and certificate ["$CLIENT_CER"]"
   keytool -genkeypair -alias $ALIAS_CLIENT -keyalg EC -dname 'CN='$CN_CLIENT -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias $ALIAS_CLIENT | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $ALIAS_CA -gencert -ext KU=dig -validity $VALIDITY -rfc > $CLIENT_CER
   keytool -alias $ALIAS_CLIENT -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_CER -noprompt

}

jobs() {
  echo "$1"
  case $1 in
  "remove")
    remove_files
    ;;
  "create")
    create_keys
    ;;
  esac
}

if [ -z "$1" ]; then
  echo "default: remove create"
  JOBS="remove create"
else
  JOBS=$@
fi

for JOB in ${JOBS}; do
  jobs ${JOB}
done
