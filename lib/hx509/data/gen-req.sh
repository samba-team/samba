#!/bin/sh
# $Id$
#

gen_cert()
{
	openssl req \
		-new \
		-subj "/CN=$1/C=SE" \
		-config openssl.cnf \
		-newkey rsa:1024 \
		-sha1 \
		-nodes \
		-keyout out.key \
		-out cert.req

        if [ "$3" = "ca" ] ; then
	    ca_arg="-signkey out.key"
	else
	    ca_arg="-CA $2.crt -CAkey $2.key -CAcreateserial"
	fi

	openssl x509 \
		-req \
		-days 3650 \
		-in cert.req \
		-extfile openssl.cnf \
		-extensions $4 \
		$ca_arg \
		-out cert.crt

	  mv cert.crt $3.crt
	  mv out.key $3.key
}

gen_cert "hx509 Test Root CA" "root" "ca" "v3_ca"
gen_cert "Test cert" "ca" "test" "usr_cert"
gen_cert "Test cert KeyEncipherment" "ca" "test" "usr_cert_ke"
gen_cert "Test cert DigitalSignature" "ca" "test" "usr_cert_ds"
gen_cert "Sub CA" "ca" "sub-ca" "v3_ca"
gen_cert "Test sub cert" "sub-ca" "sub-cert" "usr_cert"

