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
gen_cert "Test cert KeyEncipherment" "ca" "test-ke-only" "usr_cert_ke"
gen_cert "Test cert DigitalSignature" "ca" "test-ds-only" "usr_cert_ds"
gen_cert "Sub CA" "ca" "sub-ca" "v3_ca"
gen_cert "Test sub cert" "sub-ca" "sub-cert" "usr_cert"

cat sub-ca.crt ca.crt > sub-ca-combined.crt

openssl pkcs12 \
    -export \
    -in test.crt \
    -inkey test.key \
    -passout pass:foobar \
    -out test.p12 \
    -name "friendlyname-test" \
    -certfile ca.crt \
    -caname ca

openssl pkcs12 \
    -export \
    -in sub-cert.crt \
    -inkey sub-cert.key \
    -passout pass:foobar \
    -out sub-cert.p12 \
    -name "friendlyname-sub-cert" \
    -certfile sub-ca-combined.crt \
    -caname sub-ca \
    -caname ca

openssl smime \
    -sign \
    -nodetach \
    -binary \
    -in static-file \
    -signer test.crt \
    -inkey test.key \
    -outform DER \
    -out test-signed-data

openssl smime \
    -sign \
    -nodetach \
    -binary \
    -in static-file \
    -signer test.crt \
    -inkey test.key \
    -noattr \
    -outform DER \
    -out test-signed-data-noattr

openssl smime \
    -sign \
    -nodetach \
    -binary \
    -in static-file \
    -signer test.crt \
    -inkey test.key \
    -noattr \
    -nocerts \
    -outform DER \
    -out test-signed-data-noattr-nocerts

openssl smime \
    -encrypt \
    -nodetach \
    -binary \
    -in static-file \
    -outform DER \
    -out test-enveloped-aes-128 \
    -aes128 \
    test.crt
