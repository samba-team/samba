#!/bin/bash
#

set -e
set -u
#set -x

umask 022

function print_usage()
{
	echo "Usage:"
	echo ""
	echo "${0} <CNF_FILE> <CMD> [<ARG1> [<ARG2>]]"
	echo ""
	echo "${0} <CNF_FILE> init_ca"
	echo "${0} <CNF_FILE> update_crl"
	echo "${0} <CNF_FILE> publish_crl"
	echo "${0} <CNF_FILE> create_dc <DC_DNS_NAME> <DC_OBJECTGUID_HEX>"
	echo "${0} <CNF_FILE> revoke_dc <DC_DNS_NAME> <REVOKE_RESON>"
	echo "${0} <CNF_FILE> create_user <USER_PRINCIPAL_NAME>"
	echo "${0} <CNF_FILE> revoke_user <USER_PRINCIPAL_NAME> <REVOKE_RESON>"
	echo ""
}

function check_arg()
{
	local k="${1}"
	local v="${2}"

	test -n "${v}" || {
		print_usage
		echo "ERROR: CMD[${CMD}] argument <${k}> missing"
		return 1
	}

	return 0
}
CNF="${1-}"
test -n "${CNF}" || {
	print_usage
	echo "ERROR: speficy <CNF_FILE> see manage-ca.templates.d/manage-CA-example.com.cnf"
	exit 1
}
test -e "${CNF}" || {
	print_usage
	echo "ERROR: CNF_FILE[${CNF}] does not exist"
	exit 1
}
CMD="${2-}"
CMDARG1="${3-}"
CMDARG2="${4-}"

TEMPLATE_DIR="manage-ca.templates.d"
DEFAULT_VARS=""
DEFAULT_VARS="${DEFAULT_VARS} CRL_HTTP_BASE DNS_DOMAIN DEFAULT_BITS"
DEFAULT_VARS="${DEFAULT_VARS} DEFAULT_BITS DEFAULT_DAYS DEFAULT_CRL_DAYS"
DEFAULT_VARS="${DEFAULT_VARS} COUNTRY_NAME STATE_NAME LOCALITY_NAME ORGANIZATION_NAME"
DEFAULT_VARS="${DEFAULT_VARS} ORGANIZATIONAL_UNIT_NAME COMMON_NAME EMAIL_ADDRESS"

source "${CNF}"

DEFAULT_BITS=${DEFAULT_BITS:=8192}
CA_BITS=${CA_BITS:=${DEFAULT_BITS}}
DC_BITS=${DC_BITS:=${DEFAULT_BITS}}
USER_BITS=${USER_BITS:=${DEFAULT_BITS}}

CA_DAYS=${CA_DAYS:=3650}
CRL_DAYS=${CRL_DAYS:=30}
DC_DAYS=${DC_DAYS:=730}
USER_DAYS=${USER_DAYS:=730}

CA_DIR="CA-${DNS_DOMAIN}"
DEFAULT_VARS="${DEFAULT_VARS} CA_DIR"

CACERT_PEM="${CA_DIR}/Public/CA-${DNS_DOMAIN}-cert.pem"
CACERT_CER="${CA_DIR}/Public/CA-${DNS_DOMAIN}-cert.cer"
CACRL_PEM="${CA_DIR}/Public/CA-${DNS_DOMAIN}-crl.pem"
CACRL_CRL="${CA_DIR}/Public/CA-${DNS_DOMAIN}-crl.crl"
CA_SERIAL="${CA_DIR}/Private/CA-${DNS_DOMAIN}-serial.txt"

function generate_from_template()
{
	local base_template="${TEMPLATE_DIR}/$1"
	local cmd_template="${TEMPLATE_DIR}/$2"
	local cnf_file="$3"
	shift 3
	local vars="$@"

	test -f "${base_template}" || {
		echo "base_template[${base_template}] does not exists"
		return 1
	}
	test -f "${cmd_template}" || {
		echo "cmd_template[${cmd_template}] does not exists"
		return 1
	}
	test -e "${cnf_file}" && {
		echo "cnf_file[${cnf_file}] already exists"
		return 1
	}

	local sedargs=""
	for k in $vars; do
		v=$(eval echo "\${${k}}")
		sedargs="${sedargs} -e 's!@@${k}@@!${v}!g'"
	done

	#echo "sedargs[${sedargs}]"
	cat "${base_template}" "${cmd_template}" | eval sed ${sedargs} > "${cnf_file}"
	grep '@@'  "${cnf_file}" | wc -l | grep -q '^0' || {
		echo "invalid context in cnf_file[${cnf_file}]"
		grep '@@' "${cnf_file}"
		return 1
	}

	return 0
}

case "${CMD}" in
init_ca)
	test -e "${CA_DIR}" && {
		echo "CA with CA_DIR[${CA_DIR}] already exists"
		exit 1
	}

	OPENSSLCNF="${CA_DIR}/Private/CA-${DNS_DOMAIN}-openssl.cnf"
	CA_INDEX="${CA_DIR}/Private/CA-${DNS_DOMAIN}-index.txt"
	CA_CRLNUMBER="${CA_DIR}/Private/CA-${DNS_DOMAIN}-crlnumber.txt"
	PRIVATEKEY="${CA_DIR}/Private/CA-${DNS_DOMAIN}-private-key.pem"

	ORGANIZATIONAL_UNIT_NAME="CA Administration"
	COMMON_NAME="CA of ${DNS_DOMAIN}"
	EMAIL_ADDRESS="ca-${DNS_DOMAIN}@${DNS_DOMAIN}"

	DEFAULT_BITS="${CA_BITS}"
	DEFAULT_DAYS="1"
	DEFAULT_CRL_DAYS="${CRL_DAYS}"

	mkdir -p "${CA_DIR}/"{,Public}
	umask 077
	mkdir -p "${CA_DIR}/"{,Private,NewCerts,DCs,Users}
	umask 022
	touch "${CA_INDEX}"
	echo "00" > "${CA_SERIAL}"
	echo "00" > "${CA_CRLNUMBER}"

	generate_from_template \
		"openssl-BASE-template.cnf" \
		"openssl-CA-template.cnf" \
		"${OPENSSLCNF}" \
		${DEFAULT_VARS}
	openssl req -new -x509 -sha256 -extensions v3_ca -days "${CA_DAYS}" -keyout "${PRIVATEKEY}" -out "${CACERT_PEM}" -config "${OPENSSLCNF}"
	openssl x509 -in "${CACERT_PEM}" -inform PEM -out "${CACERT_CER}" -outform DER
	echo -n "Generate CRL [ENTER] to continue"
	read
	openssl ca -config "${OPENSSLCNF}" -gencrl -out "${CACRL_PEM}"
	openssl crl -in "${CACRL_PEM}" -inform PEM -out "${CACRL_CRL}" -outform DER
	ls -la "${CA_DIR}"/Public/CA-*
	echo "Please run: '${0} ${CNF} publish_crl'"
	exit 0
	;;
update_crl)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}

	OPENSSLCNF="${CA_DIR}/Private/CA-${DNS_DOMAIN}-openssl.cnf"
	openssl ca -config "${OPENSSLCNF}" -gencrl -out "${CACRL_PEM}"
	openssl crl -in "${CACRL_PEM}" -inform PEM -out "${CACRL_CRL}" -outform DER
	ls -la "${CACRL_PEM}" "${CACRL_CRL}"
	echo "Please run: '${0} ${CNF} publish_crl'"
	exit 0
	;;
publish_crl)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}

	echo "Upload ${CACRL_CRL} to ${CRL_SSH_BASE}/"
	rsync -a -P "${CACRL_CRL}" "${CRL_SSH_BASE}/"
	echo "Check ${CRL_HTTP_BASE}/CA-${DNS_DOMAIN}-crl.crl"
	exit 0
	;;
create_dc)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}
	#
	#
	# ldbsearch -H ldap://DC_DNS_NAME '(dnsHostName=DC_DNS_NAME)' distinguishedName --controls=search_options:1:1 --controls=extended_dn:1:0
	DC_DNS_NAME="${CMDARG1}"
	check_arg "DC_DNS_NAME" "${DC_DNS_NAME}"
	DC_OBJECTGUID_HEX=$(echo "${CMDARG2}" | tr a-z A-Z)
	check_arg "DC_OBJECTGUID_HEX" "${DC_OBJECTGUID_HEX}"

	DC_DIR="${CA_DIR}/DCs/${DC_DNS_NAME}"
	test -e "${DC_DIR}" && {
		echo "DC with DC_DIR[${DC_DIR}] already exists"
		exit 1
	}

	NEXT_SERIAL=$(cat "${CA_SERIAL}" | xargs)
	DCFILE_BASE="DC-${DC_DNS_NAME}-S${NEXT_SERIAL}"
	OPENSSLCNF="${DC_DIR}/${DCFILE_BASE}-openssl.cnf"
	DCKEY_PEM="${DC_DIR}/${DCFILE_BASE}-key.pem"
	DCKEY_PRIVATE_PEM="${DC_DIR}/${DCFILE_BASE}-private-key.pem"
	DCKEY_PRIVATE_PEM_BASE="${DCFILE_BASE}-private-key.pem"
	DCKEY_PRIVATE_PEM_LINK="${DC_DIR}/DC-${DC_DNS_NAME}-private-key.pem"
	DCREQ_PEM="${DC_DIR}/${DCFILE_BASE}-req.pem"
	DCCERT_PEM="${DC_DIR}/${DCFILE_BASE}-cert.pem"
	DCCERT_PEM_BASE="${DCFILE_BASE}-cert.pem"
	DCCERT_PEM_LINK="${DC_DIR}/DC-${DC_DNS_NAME}-cert.pem"
	DCCERT_CER="${DC_DIR}/${DCFILE_BASE}-cert.cer"
	DCCERT_P12="${DC_DIR}/${DCFILE_BASE}-private.p12"

	ORGANIZATIONAL_UNIT_NAME="Domain Controllers"
	COMMON_NAME="${DC_DNS_NAME}"
	EMAIL_ADDRESS="ca-${DNS_DOMAIN}@${DNS_DOMAIN}"

	DEFAULT_BITS="${DC_BITS}"
	DEFAULT_DAYS="${DC_DAYS}"
	DEFAULT_CRL_DAYS="${CRL_DAYS}"

	umask 077
	mkdir -p "${DC_DIR}/"

	generate_from_template \
		"openssl-BASE-template.cnf" \
		"openssl-DC-template.cnf" \
		"${OPENSSLCNF}" \
		${DEFAULT_VARS} DC_DNS_NAME DC_OBJECTGUID_HEX

	openssl req -new -newkey rsa:${DC_BITS} -keyout "${DCKEY_PEM}" -out "${DCREQ_PEM}" -config "${OPENSSLCNF}"
	openssl rsa -in "${DCKEY_PEM}" -inform PEM -out "${DCKEY_PRIVATE_PEM}" -outform PEM
	openssl ca -config "${OPENSSLCNF}" -in "${DCREQ_PEM}" -out "${DCCERT_PEM}"
	ln -s "${DCKEY_PRIVATE_PEM_BASE}" "${DCKEY_PRIVATE_PEM_LINK}"
	ln -s "${DCCERT_PEM_BASE}" "${DCCERT_PEM_LINK}"
	openssl x509 -in "${DCCERT_PEM}"  -inform PEM -out "${DCCERT_CER}" -outform DER
	echo "Generate ${DCCERT_P12}"
	openssl pkcs12 -in "${DCCERT_PEM}" -inkey "${DCKEY_PRIVATE_PEM}" -export -out "${DCCERT_P12}"
	ls -la "${DC_DIR}"/*.*
	exit 0
	;;
revoke_dc)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}
	DC_DNS_NAME="${CMDARG1}"
	check_arg "DC_DNS_NAME" "${DC_DNS_NAME}"
	REVOKE_REASON="${CMDARG2}"
	check_arg "REVOKE_REASON" "${REVOKE_REASON}"

	DC_DIR="${CA_DIR}/DCs/${DC_DNS_NAME}"
	test -e "${DC_DIR}" || {
		echo "DC with DC_DIR[${DC_DIR}] does not exists"
		exit 1
	}

	OPENSSLCNF="${CA_DIR}/Private/CA-${DNS_DOMAIN}-openssl.cnf"
	DCKEY_PRIVATE_PEM_LINK="${DC_DIR}/DC-${DC_DNS_NAME}-private-key.pem"
	DCCERT_PEM_LINK="${DC_DIR}/DC-${DC_DNS_NAME}-cert.pem"

	REVOKE_DATE=$(date +%Y%m%d-%H%M%S)
	REVOKE_DC_DIR="${DC_DIR}.${REVOKE_DATE}.revoked-${REVOKE_REASON}"

	openssl ca -config "${OPENSSLCNF}" -revoke "${DCCERT_PEM_LINK}" -crl_reason "${REVOKE_REASON}"

	mv "${DCKEY_PRIVATE_PEM_LINK}" "${DCKEY_PRIVATE_PEM_LINK}.revoked"
	mv "${DCCERT_PEM_LINK}" "${DCCERT_PEM_LINK}.revoked"
	mv "${DC_DIR}" "${REVOKE_DC_DIR}"
	echo "${REVOKE_DC_DIR}"

	openssl ca -config "${OPENSSLCNF}" -gencrl -out "${CACRL_PEM}"
	openssl crl -in "${CACRL_PEM}" -inform PEM -out "${CACRL_CRL}" -outform DER
	ls -la "${CACRL_PEM}" "${CACRL_CRL}"
	echo "Please run: '${0} ${CNF} publish_crl'"
	exit 0
	;;
create_user)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}
	USER_PRINCIPAL_NAME="${CMDARG1}"
	check_arg "USER_PRINCIPAL_NAME" "${USER_PRINCIPAL_NAME}"

	USER_DIR="${CA_DIR}/Users/${USER_PRINCIPAL_NAME}"
	test -e "${USER_DIR}" && {
		echo "USER with USER_DIR[${USER_DIR}] already exists"
		exit 1
	}

	NEXT_SERIAL=$(cat "${CA_SERIAL}" | xargs)
	USERFILE_BASE="USER-${USER_PRINCIPAL_NAME}-S${NEXT_SERIAL}"
	OPENSSLCNF="${USER_DIR}/${USERFILE_BASE}-openssl.cnf"
	USERKEY_PEM="${USER_DIR}/${USERFILE_BASE}-key.pem"
	USERKEY_PRIVATE_PEM="${USER_DIR}/${USERFILE_BASE}-private-key.pem"
	USERKEY_PRIVATE_PEM_BASE="${USERFILE_BASE}-private-key.pem"
	USERKEY_PRIVATE_PEM_LINK="${USER_DIR}/USER-${USER_PRINCIPAL_NAME}-private-key.pem"
	USERREQ_PEM="${USER_DIR}/${USERFILE_BASE}-req.pem"
	USERCERT_PEM="${USER_DIR}/${USERFILE_BASE}-cert.pem"
	USERCERT_PEM_BASE="${USERFILE_BASE}-cert.pem"
	USERCERT_PEM_LINK="${USER_DIR}/USER-${USER_PRINCIPAL_NAME}-cert.pem"
	USERCERT_CER="${USER_DIR}/${USERFILE_BASE}-cert.cer"
	USERCERT_P12="${USER_DIR}/${USERFILE_BASE}-private.p12"

	ORGANIZATIONAL_UNIT_NAME="Users"
	COMMON_NAME="${USER_PRINCIPAL_NAME}"
	EMAIL_ADDRESS="${USER_PRINCIPAL_NAME}"

	DEFAULT_BITS="${USER_BITS}"
	DEFAULT_DAYS="${USER_DAYS}"
	DEFAULT_CRL_DAYS="${CRL_DAYS}"

	umask 077
	mkdir -p "${USER_DIR}/"

	generate_from_template \
		"openssl-BASE-template.cnf" \
		"openssl-USER-template.cnf" \
		"${OPENSSLCNF}" \
		${DEFAULT_VARS} USER_PRINCIPAL_NAME

	openssl req -new -newkey rsa:${USER_BITS} -keyout "${USERKEY_PEM}" -out "${USERREQ_PEM}" -config "${OPENSSLCNF}"
	openssl rsa -in "${USERKEY_PEM}" -inform PEM -out "${USERKEY_PRIVATE_PEM}" -outform PEM
	openssl ca -config "${OPENSSLCNF}" -in "${USERREQ_PEM}" -out "${USERCERT_PEM}"
	ln -s "${USERKEY_PRIVATE_PEM_BASE}" "${USERKEY_PRIVATE_PEM_LINK}"
	ln -s "${USERCERT_PEM_BASE}" "${USERCERT_PEM_LINK}"
	openssl x509 -in "${USERCERT_PEM}"  -inform PEM -out "${USERCERT_CER}" -outform DER
	echo "Generate ${USERCERT_P12}"
	openssl pkcs12 -in "${USERCERT_PEM}" -inkey "${USERKEY_PRIVATE_PEM}" -export -out "${USERCERT_P12}"
	ls -la "${USER_DIR}"/*.*
	exit 0
	;;
revoke_user)
	test -e "${CA_DIR}" || {
		echo "CA with CA_DIR[${CA_DIR}] does not exists"
		exit 1
	}
	USER_PRINCIPAL_NAME="${CMDARG1}"
	check_arg "USER_PRINCIPAL_NAME" "${USER_PRINCIPAL_NAME}"
	REVOKE_REASON="${CMDARG2}"
	check_arg "REVOKE_REASON" "${REVOKE_REASON}"

	USER_DIR="${CA_DIR}/Users/${USER_PRINCIPAL_NAME}"
	test -e "${USER_DIR}" || {
		echo "USER with USER_DIR[${USER_DIR}] does not exists"
		exit 1
	}

	OPENSSLCNF="${CA_DIR}/Private/CA-${DNS_DOMAIN}-openssl.cnf"
	USERKEY_PRIVATE_PEM_LINK="${USER_DIR}/USER-${USER_PRINCIPAL_NAME}-private-key.pem"
	USERCERT_PEM_LINK="${USER_DIR}/USER-${USER_PRINCIPAL_NAME}-cert.pem"

	REVOKE_DATE=$(date +%Y%m%d-%H%M%S)
	REVOKE_USER_DIR="${USER_DIR}.${REVOKE_DATE}.revoked-${REVOKE_REASON}"

	openssl ca -config "${OPENSSLCNF}" -revoke "${USERCERT_PEM_LINK}" -crl_reason "${REVOKE_REASON}"

	mv "${USERKEY_PRIVATE_PEM_LINK}" "${USERKEY_PRIVATE_PEM_LINK}.revoked"
	mv "${USERCERT_PEM_LINK}" "${USERCERT_PEM_LINK}.revoked"
	mv "${USER_DIR}" "${REVOKE_USER_DIR}.revoked"
	echo "${REVOKE_USER_DIR}"

	openssl ca -config "${OPENSSLCNF}" -gencrl -out "${CACRL_PEM}"
	openssl crl -in "${CACRL_PEM}" -inform PEM -out "${CACRL_CRL}" -outform DER
	ls -la "${CACRL_PEM}" "${CACRL_CRL}"
	echo "Please run: '${0} ${CNF} publish_crl'"
	exit 0
	;;
usage)
	print_usage
	exit 1
	;;
*)
	print_usage
	echo "ERROR: CMD[${CMD}] - unknown"
	exit 1
	;;
esac

exit 1
