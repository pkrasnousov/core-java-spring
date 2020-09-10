#!/bin/bash

# ########################################################### #
# ########################################################### #
# #################### UTILITY FUNCTIONS #################### #
# ########################################################### #
# ########################################################### #

err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Get property from configuration file
ah_get_conf_prop() {
  echo "$(grep -Po "${AH_CONF_FILE}" -e "()(?<=^$1=).*")"
}

# Set property in configuration file
ah_set_conf_prop() {
  local out="$(echo "$2" | sed 's/[\\\/\&]/\\&/g')"
  if ! sed -i "/^$1=.*/{s//$1=${out}/;h};\${x;/./{x;q0};x;q1}" "${AH_CONF_FILE}"; then
    err "ah_set_conf_prop: Could not find $1"
  fi
}

# Set property in system properties file
ah_set_app_prop() {
  local system="$1"
  local property="$2"
  local value="$3"

  local prop_file="${AH_CONF_DIR}/systems/${system}/application.properties"

  local out="$(echo "${value}" | sed 's/[\\\/\&]/\\&/g')"
  if ! sed -i "/^${property}=.*/{s//${property}=${out}/;h};\${x;/./{x;q0};x;q1}" "${prop_file}"; then
    err "Missing [$2] in [${prop_file}]"
  fi
}

ah_subject_alternative_names() {
  out="$1"
  ips="$(echo "${@:2}" | grep -o -P '(?<=-ips ).*?((?= -dns)|$)')"
  dns="$(echo "${@:2}" | grep -o -P '(?<=-dns ).*?((?= -ips)|$)')"

  if [[ ! "${out}" =~ (^|,)"IP:127.0.0.1"(,|$) ]]; then
    [[ -n "${out}" ]] && out="${out},IP:127.0.0.1" || out="IP:127.0.0.1"
  fi
  if [[ ! "${out}" =~ (^|,)"DNS:localhost"(,|$) ]]; then
    [[ -n "${out}" ]] && out="${out},DNS:localhost" || out="DNS:localhost"
  fi

  for ip in ${ips}
  do
    if [[ ! ${out} =~ (^|,)"IP:${ip}"(,|$) ]]; then
      out="${out},IP:${ip}"
    fi
  done

  for domain in ${dns}
  do
    if [[ ! ${out} =~ (^|,)"DNS:${domain}"(,|$) ]]; then
      out="${out},DNS:${domain}"
    fi
  done

  echo "${out}"
}

# ########################################################### #
# ########################################################### #
# ################## UTILITY FUNCTIONS END ################## #
# ########################################################### #
# ########################################################### #

# ########################################################### #
# ########################################################### #
# ################# VARIABLE INITIALIZATION ################# #
# ########################################################### #
# ########################################################### #

if [[ -z "$AH_CONF_DIR" ]]; then
  AH_CONF_DIR="/etc/arrowhead"
fi
if [[ -z "$AH_CLOUDS_DIR" ]]; then
  AH_CLOUDS_DIR="${AH_CONF_DIR}/clouds"
fi
if [[ -z "$AH_SYSTEMS_DIR" ]]; then
  AH_SYSTEMS_DIR="${AH_CONF_DIR}/systems"
fi
if [[ -z "$AH_CONF_FILE" ]]; then
  AH_CONF_FILE="${AH_CONF_DIR}/arrowhead.cfg"
fi
if [[ -z "$AH_RELAYS_DIR" ]]; then
  AH_RELAYS_DIR="${AH_CONF_DIR}/relays"
fi

AH_PASS_CERT="$(ah_get_conf_prop cert_password)"
AH_CLOUD_NAME="$(ah_get_conf_prop cloudname)"
AH_OPERATOR="$(ah_get_conf_prop operator)"
AH_COMPANY=arrowhead # hard-coded to the Arrowhead Framework
AH_COUNTRY=eu # hard-coded to the Arrowhead Framework

AH_RELAY_MASTER_CERT="$(ah_get_conf_prop relay_master_cert)"
AH_DOMAIN_NAME="$(ah_get_conf_prop domain_name)"

AH_SYSTEM_INTERFACE="$(ah_get_conf_prop system_interface)"

AH_NETWORK_INTERFACES="$(ah_get_conf_prop san_interfaces)"
SAN_IPS="$(ah_get_conf_prop san_ips)"
SAN_DNS="$(ah_get_conf_prop san_dns)"

OWN_IP="$(echo "${AH_SYSTEM_INTERFACE}" | awk ' { print $2 } ')"

readarray -t SAN_INTERFACE_IPS<<<"$(echo "${AH_NETWORK_INTERFACES}" | awk ' BEGIN { RS = "," } { print $2 } ')"

# ########################################################### #
# ########################################################### #
# ############### VARIABLE INITIALIZATION END ############### #
# ########################################################### #
# ########################################################### #

# ########################################################### #
# ########################################################### #
# #################### WRAPPER FUNCTIONS #################### #
# ########################################################### #
# ########################################################### #

ah_cert_signed_system() {
  local system_name=$1
  
  local root_cn="${AH_COMPANY}.${AH_COUNTRY}"
  local cloud_cn="${AH_CLOUD_NAME}.${AH_OPERATOR}.${AH_COMPANY}.${AH_COUNTRY}"
  local system_cn="${system_name}.${AH_CLOUD_NAME}.${AH_OPERATOR}.${AH_COMPANY}.${AH_COUNTRY}"
  local sans="$(ah_subject_alternative_names)"
  sans="$(ah_subject_alternative_names "${sans}" -ips "${SAN_INTERFACE_IPS[@]}" "${SAN_IPS}" -dns "$(hostname)" "${SAN_DNS}")"

  if [[ "${system_name}" != "sysop" ]]; then
    create_system_keystore \
      "${AH_CONF_DIR}/master.p12" "${root_cn}" \
      "${AH_CLOUDS_DIR}/${AH_CLOUD_NAME}.p12" "${cloud_cn}" \
      "${AH_SYSTEMS_DIR}/${system_name}/${system_name}.p12" "${system_cn}" \
      "${sans}"
  else
    create_sysop_keystore \
      "${AH_CONF_DIR}/master.p12" "${root_cn}" \
      "${AH_CLOUDS_DIR}/${AH_CLOUD_NAME}.p12" "${cloud_cn}" \
      "${AH_SYSTEMS_DIR}/${system_name}/${system_name}.p12" "${system_cn}" \
      "${sans}"
  fi
}

ah_ca_keystore() {
  local system_name=$1

  local root_cn="${AH_COMPANY}.${AH_COUNTRY}"
  local cloud_cn="${AH_CLOUD_NAME}.${AH_OPERATOR}.${AH_COMPANY}.${AH_COUNTRY}"
  local system_cn="${system_name}.${AH_CLOUD_NAME}.${AH_OPERATOR}.${AH_COMPANY}.${AH_COUNTRY}"
  local sans="$(ah_subject_alternative_names)"
  sans="$(ah_subject_alternative_names "${sans}" -ips "${SAN_INTERFACE_IPS[@]}" "${SAN_IPS}" -dns "$(hostname)" "${SAN_DNS}")"

  create_ca_system_keystore \
    "${AH_CONF_DIR}/master.p12" "${root_cn}" \
    "${AH_CLOUDS_DIR}/${AH_CLOUD_NAME}.p12" "${cloud_cn}" \
    "${AH_SYSTEMS_DIR}/${system_name}/${system_name}.p12" "${system_cn}" \
    "${sans}"
}

# ########################################################### #
# ########################################################### #
# ################## WRAPPER FUNCTIONS END ################## #
# ########################################################### #
# ########################################################### #

# ########################################################### #
# ########################################################### #
# #################### LIBRARY FUNCTIONS #################### #
# ########################################################### #
# ########################################################### #

# Creates a root certificate keystore and a corresponding PEM certificate.
#
# If the keystore already exists, the operation does nothing. If the PEM
# cerificate is missing, it will be created either from the already
# existing or new keystore.
#
# @param $1 Path to desired root certificate keystore.
# @param $2 Desired Common Name of root certificate.
create_root_keystore() {
  local root_keystore=$1
  local root_key_alias=$2
  local root_cert_file="${root_keystore%.*}.crt"

  if [ ! -f "${root_keystore}" ]; then
    echo -e "\e[34mCreating \e[33m${root_keystore}\e[34m ...\e[0m"
    mkdir -p "$(dirname "${root_keystore}")"
    rm -f "${root_cert_file}"

    keytool -genkeypair -v \
      -keystore "${root_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -keyalg "RSA" \
      -keysize "2048" \
      -validity "3650" \
      -alias "${root_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -dname "CN=${root_key_alias}, OU=${AH_OPERATOR}, O=arrowhead, C=eu" \
      -ext "BasicConstraints=ca:true,pathlen:3"
  fi

  if [ ! -f "${root_cert_file}" ]; then
    echo -e "\e[34mCreating \e[33m${root_cert_file}\e[34m ...\e[0m"

    keytool -exportcert -v \
      -keystore "${root_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${root_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -file "${root_cert_file}" \
      -rfc
  fi
}

# Creates a cloud certificate keystore, containing a certificate signed by the
# specified root, and a corresponding PEM certificate.
#
# If the keystore already exists, the operation does nothing. If the PEM
# cerificate is missing, it will be created either from the already
# existing or new keystore. If the root keystore has changed since an
# existing cloud keystore was created, it is recreated.
#
# @param $1 Path to root certificate keystore.
# @param $2 Common Name of root certificate.
# @param $3 Path to desired cloud certificate keystore.
# @param $4 Desired Common Name of cloud certificate.
create_cloud_keystore() {
  local root_keystore=$1
  local root_key_alias=$2
  local root_cert_file="${root_keystore%.*}.crt"
  local cloud_keystore=$3
  local cloud_key_alias=$4
  local cloud_cert_file="${cloud_keystore%.*}.crt"
  local relay=$5

  if [ -n "${relay}" ]; then
    local op="relay"
  else
    local op="${AH_OPERATOR}"
  fi

  if [ -f "${cloud_keystore}" ] && [ "${root_keystore}" -nt "${cloud_keystore}" ]; then
    rm -f "${cloud_keystore}"
  fi

  if [ ! -f "${cloud_keystore}" ]; then
    echo -e "\e[34mCreating \e[33m${cloud_keystore}\e[34m ...\e[0m"
    mkdir -p "$(dirname "${cloud_keystore}")"
    rm -f "${cloud_cert_file}"

    keytool -genkeypair -v \
      -keystore "${cloud_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -keyalg "RSA" \
      -keysize "2048" \
      -validity "3650" \
      -alias "${cloud_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -dname "CN=${cloud_key_alias}, OU=${op}, O=arrowhead, C=eu" \
      -ext "BasicConstraints=ca:true,pathlen:2"

    keytool -importcert -v \
      -keystore "${cloud_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${root_key_alias}" \
      -file "${root_cert_file}" \
      -trustcacerts \
      -noprompt

    keytool -certreq -v \
      -keystore "${cloud_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${cloud_key_alias}" \
      -keypass "${AH_PASS_CERT}" |
      keytool -gencert -v \
        -keystore "${root_keystore}" \
        -storepass "${AH_PASS_CERT}" \
        -validity "3650" \
        -alias "${root_key_alias}" \
        -keypass "${AH_PASS_CERT}" \
        -ext "BasicConstraints=ca:true,pathlen:2" \
        -rfc |
      keytool -importcert \
        -keystore "${cloud_keystore}" \
        -storepass "${AH_PASS_CERT}" \
        -alias "${cloud_key_alias}" \
        -keypass "${AH_PASS_CERT}" \
        -trustcacerts \
        -noprompt
  fi

  if [ ! -f "${cloud_cert_file}" ]; then
    echo -e "\e[34mCreating \e[33m${cloud_cert_file}\e[34m ...\e[0m"

    keytool -exportcert -v \
      -keystore "${cloud_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${cloud_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -file "${cloud_cert_file}" \
      -rfc
  fi
}

# Creates a system certificate keystore, containing a certificate signed by
# the specified cloud, and a corresponding PEM certificate.
#
# If the keystore already exists, the operation does nothing. If the
# PEM cerificate is missing, it will be created either
# from the already existing or the new keystore. If the cloud keystore has changed
# since an existing system keystore was created, it is recreated.
#
# @param $1 Path to root certificate keystore.
# @param $2 Common Name of root certificate.
# @param $3 Path to cloud certificate keystore.
# @param $4 Common Name of cloud certificate.
# @param $5 Path to desired system certificate keystore.
# @param $6 Desired Common Name of system certificate.
create_system_keystore() {
  local root_keystore=$1
  local root_key_alias=$2
  local root_cert_file="${root_keystore%.*}.crt"
  local cloud_keystore=$3
  local cloud_key_alias=$4
  local cloud_cert_file="${cloud_keystore%.*}.crt"
  local system_keystore=$5
  local system_key_alias=$6
  local san=$7

  if [ -f "${system_keystore}" ] && [ "${cloud_keystore}" -nt "${system_keystore}" ]; then
    rm -f "${system_keystore}"
  fi

  if [ ! -f "${system_keystore}" ]; then
    echo -e "\e[34mCreating \e[33m${system_keystore}\e[34m ...\e[0m"
    mkdir -p "$(dirname "${system_keystore}")"

    keytool -genkeypair -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -keyalg "RSA" \
      -keysize "2048" \
      -validity "3650" \
      -alias "${system_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -dname "CN=${system_key_alias}, OU=${AH_OPERATOR}, O=arrowhead, C=eu" \
      -ext "SubjectAlternativeName=${san}"

    keytool -importcert -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${root_key_alias}" \
      -file "${root_cert_file}" \
      -trustcacerts \
      -noprompt

    keytool -importcert -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${cloud_key_alias}" \
      -file "${cloud_cert_file}" \
      -trustcacerts \
      -noprompt

    keytool -certreq -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${system_key_alias}" \
      -keypass "${AH_PASS_CERT}" |
      keytool -gencert -v \
        -keystore "${cloud_keystore}" \
        -storepass "${AH_PASS_CERT}" \
        -validity "3650" \
        -alias "${cloud_key_alias}" \
        -keypass "${AH_PASS_CERT}" \
        -ext "SubjectAlternativeName=${san}" \
        -rfc |
      keytool -importcert \
        -keystore "${system_keystore}" \
        -storepass "${AH_PASS_CERT}" \
        -alias "${system_key_alias}" \
        -keypass "${AH_PASS_CERT}" \
        -trustcacerts \
        -noprompt
  fi
}

# Create the keystore for the CA system
# Apart from being a regular Arrowhead compliant system keystore,
# it also has to contain the private key of the cloud
#
# If the keystore already exists, the operation does nothing. If the
# PEM cerificate is missing, it will be created either
# from the already existing or the new keystore. If the cloud keystore has changed
# since an existing system keystore was created, it is recreated.
#
# @param $1 Path to root certificate keystore.
# @param $2 Common Name of root certificate.
# @param $3 Path to cloud certificate keystore.
# @param $4 Common Name of cloud certificate.
# @param $5 Path to desired system certificate keystore.
# @param $6 Desired Common Name of system certificate.
# @param $7 Subject alternative names for system certificate.
create_ca_system_keystore() {
  local root_keystore=$1
  local root_key_alias=$2
  local root_cert_file="${root_keystore%.*}.crt"
  local cloud_keystore=$3
  local cloud_key_alias=$4
  local cloud_cert_file="${cloud_keystore%.*}.crt"
  local system_keystore=$5
  local system_key_alias=$6
  local san=$7

  if [ ! -f "${system_keystore}" ]; then
    echo -e "\e[34mCreating \e[33m${system_keystore}\e[34m ...\e[0m"
    mkdir -p "$(dirname "${system_keystore}")"
    rm -f "${system_pub_file}"

    keytool -genkeypair -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -keyalg "RSA" \
      -keysize "2048" \
      -validity "3650" \
      -alias "${system_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -dname "CN=${system_key_alias}, OU=${AH_OPERATOR}, O=arrowhead, C=eu" \
      -ext "SubjectAlternativeName=${san}"

    keytool -importcert -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${root_key_alias}" \
      -file "${root_cert_file}" \
      -trustcacerts \
      -noprompt

    # import cloud keypair
    # this is necessary, because CA signs system certificates with the cloud cert
    keytool -importkeystore -v \
      -srckeypass "${AH_PASS_CERT}" \
      -srcstorepass "${AH_PASS_CERT}" \
      -destkeypass "${AH_PASS_CERT}" \
      -deststorepass  "${AH_PASS_CERT}" \
      -srcalias "${cloud_key_alias}" \
      -destalias "${cloud_key_alias}" \
      -srckeystore "${cloud_keystore}" \
      -destkeystore "${system_keystore}" \
      -deststoretype PKCS12

    # sign CA system cert with the cloud cert
    keytool -certreq -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${system_key_alias}" \
      -keypass "${AH_PASS_CERT}" |
      keytool -gencert -v \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -validity "3650" \
      -alias "${cloud_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -ext "SubjectAlternativeName=${san}" \
      -rfc |
      keytool -importcert \
      -keystore "${system_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${system_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -noprompt
  fi
}

# Creates a system operator certificate keystore, containing a certificate
# signed by the specified cloud, a PEM certificate file, a CA (Certificate
# Authority) file, a public key file and a private key file.
#
# If the keystore already exists, the operation does nothing. If the PEM
# cerificate is missing, it will be created either from the already
# existing or new keystore. If the cloud keystore has changed since an
# existing system operator keystore was created, it is recreated.
#
# @param $1 Path to root certificate keystore.
# @param $2 Common Name of root certificate.
# @param $3 Path to cloud certificate keystore.
# @param $4 Common Name of cloud certificate.
# @param $5 Path to desired system operator certificate keystore.
# @param $6 Desired Common Name of system operator certificate.
create_sysop_keystore() {
  local root_keystore=$1
  local root_cert_file="${root_keystore%.*}.crt"
  local cloud_keystore=$3
  local cloud_cert_file="${cloud_keystore%.*}.crt"
  local sysop_keystore=$5
  local sysop_key_alias=$6
  local sysop_pub_file="${sysop_keystore%.*}.pub"
  local sysop_ca_file="${sysop_keystore%.*}.ca"
  local sysop_cert_file="${sysop_keystore%.*}.crt"
  local sysop_key_file="${sysop_keystore%.*}.key"

  local create_keystore_or_pub_file=0

  if [ -f "${sysop_keystore}" ] && [ "${cloud_keystore}" -nt "${sysop_keystore}" ]; then
    rm -f "${sysop_keystore}"
  fi

  if [ ! -f "${sysop_keystore}" ]; then
    rm -f "${sysop_ca_file}"
    rm -f "${sysop_cert_file}"
    rm -f "${sysop_key_file}"
    create_keystore_or_pub_file=1
  fi

  if [ ! -f "${sysop_pub_file}" ]; then
    create_keystore_or_pub_file=1
  fi

  if [[ "${create_keystore_or_pub_file}" == "1" ]]; then
    create_system_keystore "$1" "$2" "$3" "$4" "$5" "$6" "dns:localost,ip:127.0.0.1"
  fi

  if [ ! -f "${sysop_ca_file}" ]; then
    echo -e "\e[34mCreating \e[33m${sysop_ca_file}\e[34m ...\e[0m"

    cat "${root_cert_file}" >"${sysop_ca_file}"
    cat "${cloud_cert_file}" >>"${sysop_ca_file}"
  fi

  if [ ! -f "${sysop_cert_file}" ]; then
    echo -e "\e[34mCreating \e[33m${sysop_cert_file}\e[34m ...\e[0m"

    keytool -exportcert -v \
      -keystore "${sysop_keystore}" \
      -storepass "${AH_PASS_CERT}" \
      -alias "${sysop_key_alias}" \
      -keypass "${AH_PASS_CERT}" \
      -rfc >>"${sysop_cert_file}"
  fi

  if [ ! -f "${sysop_key_file}" ]; then
    echo -e "\e[34mCreating \e[33m${sysop_key_file}\e[34m ...\e[0m"

    openssl pkcs12 \
      -in "${sysop_keystore}" \
      -passin "pass:${AH_PASS_CERT}" \
      -out "${sysop_key_file}" \
      -nocerts \
      -nodes
  fi
}

# Creates truststore and populates it with identified certificates.
#
# If the truststore already exists, the operation does nothing. Unless,
# however, any of the identified certificate files are newer than the
# the truststore, in which case the truststore is recreated.
#
# $1        Path to desired truststore.
# $2,4,6... Paths to certificate file ".crt".
# $3,5,7... Common Names of certificates in ".crt" files.
create_truststore() {
  local truststore=$1
  local argc=$#
  local argv=("$@")

  if [ -f "${truststore}" ]; then
    for ((j = 1; j < argc; j = j + 2)); do
      local FILE="${argv[j]}"
      if [ -f "${FILE}" ] && [ "${truststore}" -nt "${FILE}" ]; then
        rm -f "${FILE}"
      fi
    done
  fi

  if [ ! -f "${truststore}" ]; then
    echo -e "\e[34mCreating \e[33m${truststore}\e[34m ...\e[0m"
    mkdir -p "$(dirname "${truststore}")"

    for ((j = 1; j < argc; j = j + 2)); do
      keytool -importcert -v \
        -keystore "${truststore}" \
        -storepass "${AH_PASS_CERT}" \
        -file "${argv[j]}" \
        -alias "${argv[j + 1]}" \
        -trustcacerts \
        -noprompt
    done
  fi
}

# ########################################################### #
# ########################################################### #
# ################## LIBRARY FUNCTIONS END ################## #
# ########################################################### #
# ########################################################### #

# Only use this in maintainer scripts.
# Do not call this in the `arrowhead` command
ah_db_tables_and_user () {
  mysql_user_name=${1}
  priv_file_name=${2}
  system_passwd=${3}

  db_get arrowhead-core-common/db_host; db_host=$RET || true

  if mysql -u root -h ${db_host} -e "SHOW DATABASES" >/dev/null 2>/dev/null; then
    mysql -u root -h ${db_host} < /usr/share/arrowhead/conf/create_arrowhead_tables.sql
    mysql -u root -h ${db_host} <<EOF
DROP USER IF EXISTS '${mysql_user_name}'@'localhost';
DROP USER IF EXISTS '${mysql_user_name}'@'%';
CREATE USER	'${mysql_user_name}'@'localhost' IDENTIFIED BY '${system_passwd}';
CREATE USER '${mysql_user_name}'@'%' IDENTIFIED BY '${system_passwd}';
EOF

    mysql -u root -h ${db_host} < /usr/share/arrowhead/conf/${priv_file_name}
  else
    db_input critical arrowhead-core-common/mysql_password_root || true
    db_go || true
    db_get arrowhead-core-common/mysql_password_root; AH_MYSQL_ROOT=$RET

    OPT_FILE="$(mktemp -q --tmpdir "arrowhead-core-common.XXXXXX")"
    trap 'rm -f "${OPT_FILE}"' EXIT
    chmod 0600 "${OPT_FILE}"

    cat >"${OPT_FILE}" <<EOF
[client]
password="${AH_MYSQL_ROOT}"
EOF

    mysql --defaults-extra-file="${OPT_FILE}" -h ${db_host} -u root < /usr/share/arrowhead/conf/create_arrowhead_tables.sql
    mysql --defaults-extra-file="${OPT_FILE}" -h ${db_host} -u root <<EOF
DROP USER IF EXISTS '${mysql_user_name}'@'localhost';
DROP USER IF EXISTS '${mysql_user_name}'@'%';
CREATE USER	'${mysql_user_name}'@'localhost' IDENTIFIED BY '${system_passwd}';
CREATE USER '${mysql_user_name}'@'%' IDENTIFIED BY '${system_passwd}';
EOF

    mysql --defaults-extra-file="${OPT_FILE}" -h ${db_host} -u root < /usr/share/arrowhead/conf/${priv_file_name}
  fi
}

ah_transform_log_file () {
  log_path=${1}

  mv ${log_path}/log4j2.xml ${log_path}/log4j2.xml.orig
  sed -r '\|^.*<Property name=\"LOG_DIR\">|s|(.*)$|<Property name=\"LOG_DIR\">/var/log/arrowhead</Property>|' ${log_path}/log4j2.xml.orig > ${log_path}/log4j2.xml
  rm ${log_path}/log4j2.xml.orig
  chown :arrowhead ${log_path}/log4j2.xml
  chmod 640 ${log_path}/log4j2.xml
} 
