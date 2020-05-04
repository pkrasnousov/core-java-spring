#!/bin/bash

# Passwords
KEY_STORE_PWD=123456
TRUST_STORE_PWD=123456

# Certs configuration
VALIDITY=365
C=CA
L=Europe
O=Arrowhead
OU=Arrowhead

MASTER_ALIAS=arrowhead.eu
CLOUD_ALIAS=testcloud2.aitia.arrowhead.eu
SERVICE_ALIAS=service_registry

# KEY & TRUST STORES - Files Names
TRUST_STORE_ORIGINAL=master.p12
KEY_STORE=keystore.p12
TRUST_STORE=truststore.p12


# CSR & CER - Files Names
MASTER_CER=master.crt
CLOUD_CER=cloud.crt
SERVICE_CER=service.crt


# PKCS12 - Files Names
CLOUD_KEY_STORE_P12=cloud.p12

# PEM - Files Names
TRUST_STORE_PEM=trustStore.pem
SERVER_KEY_STORE_PEM=server.pem


remove_keys() {
	rm -f $KEY_STORE $TRUST_STORE
	rm -f $CLOUD_CER 
	rm -f $CLOUD_KEY_STORE_P12
	rm -f $CLOUD_KEY_STORE_PEM $TRUST_STORE_PEM
}

create_keys() {
   echo "copying original trustStore"
   cp $TRUST_STORE_ORIGINAL $TRUST_STORE

   echo "creating cloud key and certificate..."
   keytool -importcert -ext bc=ca:true,pathlen:3 -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias $MASTER_ALIAS -file $MASTER_CER -noprompt


   keytool -genkeypair -alias $CLOUD_ALIAS  -keyalg RSA -keysize 2048 -dname 'CN='$CLOUD_ALIAS -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD 
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias $CLOUD_ALIAS | keytool -ext bc=ca:true,pathlen:3 -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $MASTER_ALIAS -gencert -ext KU=dig -validity $VALIDITY -rfc > $CLOUD_CER
   keytool -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias $CLOUD_ALIAS -file $CLOUD_CER -noprompt
   

   # keytool -genkeypair -alias $SERVICE_ALIAS  -ext bc=ca:true,pathlen:3 -keyalg RSA -keysize 2048 -dname 'CN='$SERVICE_ALIAS'.'$CLOUD_ALIAS -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD 
   #keytool -ext bc=ca:true,pathlen:3 -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias $SERVICE_ALIAS | keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias $CLOUD_ALIAS -gencert -ext KU=dig -validity $VALIDITY -rfc > $SERVICE_CER
   #keytool -importcert -ext bc=ca:true,pathlen:3 -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias $SERVICE_ALIAS -file $SERVICE_CER -noprompt
   
   echo "DONE!"
}

export_p12() {
   echo "exporting keys into PKCS#12 format"
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD   -alias $CLOUD_ALIAS      -destkeystore $CLOUD_KEY_STORE_P12       -deststorepass $KEY_STORE_PWD   -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD   -alias $MASTER_ALIAS      -destkeystore $CLOUD_KEY_STORE_P12       -deststorepass $KEY_STORE_PWD   -deststoretype PKCS12
   # keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias ca          -destkeystore $CA_TRUST_STORE_P12         -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   # keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD                    -destkeystore $TRUST_STORE_P12            -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
}

export_pem() {
   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting keys into PEM format"
      # openssl pkcs12 -in $SERVER_KEY_STORE_P12       -passin pass:$KEY_STORE_PWD   -nodes  -out $SERVER_KEY_STORE_PEM
      # openssl pkcs12 -in $CA_TRUST_STORE_P12         -passin pass:$TRUST_STORE_PWD -nokeys -out $CA_TRUST_STORE_PEM
      # openssl pkcs12 -in $TRUST_STORE_P12            -passin pass:$TRUST_STORE_PWD -nokeys -out $TRUST_STORE_PEM
   fi
} 

jobs () {
  echo "$1"
  case $1 in
     "remove")
        remove_keys
	;;
     "create")
        create_keys
	;;
     "export")
        export_p12
        export_pem
	;;
  esac
}

if [ -z "$1" ]  ; then
     echo "default: remove create export"
     JOBS="remove create export"
else 
     JOBS=$@	
fi

for JOB in ${JOBS}; do
   jobs ${JOB}
done