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
		-out cert.req > /dev/null 2>/dev/null

        if [ "$3" = "ca" ] ; then
	    openssl x509 \
		-req \
		-days 3650 \
		-in cert.req \
		-extfile openssl.cnf \
		-extensions $4 \
                -signkey out.key \
		-out cert.crt

		ln -s ca.crt `openssl x509 -hash -noout -in cert.crt`.0
	else

	    openssl ca \
		-name $4 \
		-days 3650 \
		-cert $2.crt \
		-keyfile $2.key \
		-in cert.req \
		-out cert.crt \
		-outdir . \
		-batch \
		-config openssl.cnf 
	fi

	mv cert.crt $3.crt
	mv out.key $3.key
}

echo "01" > serial
> index.txt
rm -f *.0

gen_cert "hx509 Test Root CA" "root" "ca" "v3_ca"
gen_cert "OCSP responder" "ca" "ocsp-responder" "ocsp"
gen_cert "Test cert" "ca" "test" "usr"
gen_cert "Revoke cert" "ca" "revoke" "usr"
gen_cert "Test cert KeyEncipherment" "ca" "test-ke-only" "usr_ke"
gen_cert "Test cert DigitalSignature" "ca" "test-ds-only" "usr_ds"
gen_cert "Sub CA" "ca" "sub-ca" "subca"
gen_cert "Test sub cert" "sub-ca" "sub-cert" "usr"

cat sub-ca.crt ca.crt > sub-ca-combined.crt

openssl ca \
    -name usr \
    -cert ca.crt \
    -keyfile ca.key \
    -revoke revoke.crt \
    -config openssl.cnf 

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

echo ocsp requests

openssl ocsp \
    -issuer ca.crt \
    -cert test.crt \
    -reqout ocsp-req1.der

openssl ocsp \
    -index index.txt \
    -rsigner ocsp-responder.crt \
    -rkey ocsp-responder.key \
    -CA ca.crt \
    -reqin ocsp-req1.der \
    -noverify \
    -respout ocsp-resp1-ocsp.der

openssl ocsp \
    -index index.txt \
    -rsigner ca.crt \
    -rkey ca.key \
    -CA ca.crt \
    -reqin ocsp-req1.der \
    -noverify \
    -respout ocsp-resp1-ca.der

openssl ocsp \
    -index index.txt \
    -rsigner ocsp-responder.crt \
    -rkey ocsp-responder.key \
    -CA ca.crt \
    -resp_no_certs \
    -reqin ocsp-req1.der \
    -noverify \
    -respout ocsp-resp1-ocsp-no-cert.der

openssl ocsp \
    -index index.txt \
    -rsigner ocsp-responder.crt \
    -rkey ocsp-responder.key \
    -CA ca.crt \
    -reqin ocsp-req1.der \
    -resp_key_id \
    -noverify \
    -respout ocsp-resp1-keyhash.der

openssl ocsp \
    -issuer ca.crt \
    -cert revoke.crt \
    -reqout ocsp-req2.der

openssl ocsp \
    -index index.txt \
    -rsigner ocsp-responder.crt \
    -rkey ocsp-responder.key \
    -CA ca.crt \
    -reqin ocsp-req2.der \
    -noverify \
    -respout ocsp-resp2.der

openssl ca \
    -gencrl \
    -name usr \
    -crldays 3600 \
    -keyfile ca.key \
    -cert ca.crt \
    -crl_reason superseded \
    -out crl1.crl \
    -config openssl.cnf 

openssl crl -in crl1.crl -outform der -out crl1.der
