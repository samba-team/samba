heimdalbuildsrcdir = $(heimdalsrcdir)/../heimdal_build

HEIMDAL_VPATH = $(heimdalbuildsrcdir):$(heimdalsrcdir)/lib/asn1:$(heimdalsrcdir)/lib/krb5:$(heimdalsrcdir)/lib/gssapi:$(heimdalsrcdir)/lib/hdb:$(heimdalsrcdir)/lib/roken:$(heimdalsrcdir)/lib/des

#######################
# Start SUBSYSTEM HEIMDAL_KDC
[SUBSYSTEM::HEIMDAL_KDC]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/kdc
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_KRB5 HEIMDAL_HDB HEIMDAL_HEIM_ASN1 \
		HEIMDAL_DIGEST_ASN1 HEIMDAL_KX509_ASN1 HEIMDAL_NTLM HEIMDAL_HCRYPTO
# End SUBSYSTEM HEIMDAL_KDC
#######################


HEIMDAL_KDC_OBJ_FILES = \
	$(heimdalsrcdir)/kdc/default_config.o \
	$(heimdalsrcdir)/kdc/kerberos5.o \
	$(heimdalsrcdir)/kdc/krb5tgs.o \
	$(heimdalsrcdir)/kdc/pkinit.o \
	$(heimdalsrcdir)/kdc/log.o \
	$(heimdalsrcdir)/kdc/misc.o \
	$(heimdalsrcdir)/kdc/524.o \
	$(heimdalsrcdir)/kdc/kerberos4.o \
	$(heimdalsrcdir)/kdc/kaserver.o \
	$(heimdalsrcdir)/kdc/digest.o \
	$(heimdalsrcdir)/kdc/process.o \
	$(heimdalsrcdir)/kdc/windc.o \
	$(heimdalsrcdir)/kdc/kx509.o

[SUBSYSTEM::HEIMDAL_NTLM]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/ntlm
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_HCRYPTO HEIMDAL_KRB5

HEIMDAL_NTLM_OBJ_FILES = \
	$(heimdalsrcdir)/lib/ntlm/ntlm.o

[SUBSYSTEM::HEIMDAL_HDB_KEYS]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/hdb
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_HCRYPTO HEIMDAL_KRB5 \
					   HEIMDAL_HDB_ASN1

HEIMDAL_HDB_KEYS_OBJ_FILES = $(heimdalsrcdir)/lib/hdb/keys.o

#######################
# Start SUBSYSTEM HEIMDAL_HDB
[SUBSYSTEM::HEIMDAL_HDB]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/hdb
PRIVATE_DEPENDENCIES = HDB_LDB HEIMDAL_KRB5 HEIMDAL_HDB_KEYS HEIMDAL_ROKEN HEIMDAL_HCRYPTO HEIMDAL_COM_ERR HEIMDAL_HDB_ASN1
# End SUBSYSTEM HEIMDAL_HDB
#######################

HEIMDAL_HDB_OBJ_FILES = \
	$(heimdalsrcdir)/lib/hdb/db.o \
	$(heimdalsrcdir)/lib/hdb/dbinfo.o \
	$(heimdalsrcdir)/lib/hdb/hdb.o \
	$(heimdalsrcdir)/lib/hdb/ext.o \
	$(heimdalsrcdir)/lib/hdb/keytab.o \
	$(heimdalsrcdir)/lib/hdb/mkey.o \
	$(heimdalsrcdir)/lib/hdb/ndbm.o \
	$(heimdalsrcdir)/lib/hdb/hdb_err.o

#######################
# Start SUBSYSTEM HEIMDAL_GSSAPI
[SUBSYSTEM::HEIMDAL_GSSAPI]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/gssapi -I$(heimdalsrcdir)/lib/gssapi/gssapi -I$(heimdalsrcdir)/lib/gssapi/spnego -I$(heimdalsrcdir)/lib/gssapi/krb5 -I$(heimdalsrcdir)/lib/gssapi/mech
PRIVATE_DEPENDENCIES = HEIMDAL_HCRYPTO HEIMDAL_HEIM_ASN1 HEIMDAL_SPNEGO_ASN1 HEIMDAL_ROKEN HEIMDAL_KRB5
# End SUBSYSTEM HEIMDAL_GSSAPI
#######################

HEIMDAL_GSSAPI_OBJ_FILES = \
	$(heimdalsrcdir)/lib/gssapi/mech/context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_krb5.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_mech_switch.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_process_context_token.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_buffer_set.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_add_cred.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_add_oid_set_member.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_compare_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_release_oid_set.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_create_empty_oid_set.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_decapsulate_token.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_cred_by_oid.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_canonicalize_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_sec_context_by_oid.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_names_for_mech.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_mechs_for_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_wrap_size_limit.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_names.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_verify.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_display_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_duplicate_oid.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_display_status.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_release_buffer.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_release_oid.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_test_oid_set_member.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_release_cred.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_set_sec_context_option.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_export_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_seal.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_acquire_cred.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_unseal.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_verify_mic.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_accept_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_cred_by_mech.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_indicate_mechs.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_delete_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_sign.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_utils.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_init_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_oid_equal.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_oid_to_str.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_context_time.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_encapsulate_token.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_get_mic.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_import_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_cred.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_wrap.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_import_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_duplicate_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_unwrap.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_export_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_inquire_context.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_release_name.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_set_cred_option.o \
	$(heimdalsrcdir)/lib/gssapi/mech/gss_pseudo_random.o \
	$(heimdalsrcdir)/lib/gssapi/asn1_GSSAPIContextToken.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/init_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/external.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/compat.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/context_stubs.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/cred_stubs.o \
	$(heimdalsrcdir)/lib/gssapi/spnego/accept_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/copy_ccache.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/delete_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/init_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/context_time.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/init.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/address_to_krb5addr.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/get_mic.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/add_cred.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_cred.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_cred_by_oid.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_cred_by_mech.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_mechs_for_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_names_for_mech.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/indicate_mechs.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/inquire_sec_context_by_oid.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/export_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/import_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/duplicate_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/import_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/compare_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/export_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/canonicalize_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/unwrap.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/wrap.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/release_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/cfx.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/8003.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/arcfour.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/encapsulate.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/display_name.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/sequence.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/display_status.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/release_buffer.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/external.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/compat.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/acquire_cred.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/release_cred.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/set_cred_option.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/decapsulate.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/verify_mic.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/accept_sec_context.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/set_sec_context_option.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/process_context_token.o \
	$(heimdalsrcdir)/lib/gssapi/krb5/prf.o


#######################
# Start SUBSYSTEM HEIMDAL_KRB5
[SUBSYSTEM::HEIMDAL_KRB5]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/krb5 -I$(heimdalsrcdir)/lib/asn1 -I$(heimdalsrcdir)/lib/com_err 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_PKINIT_ASN1 HEIMDAL_WIND \
		HEIMDAL_KRB5_ASN1 HEIMDAL_GLUE HEIMDAL_HX509 HEIMDAL_HCRYPTO
# End SUBSYSTEM HEIMDAL_KRB5
#######################

HEIMDAL_KRB5_OBJ_FILES = \
	$(heimdalsrcdir)/lib/krb5/acache.o \
	$(heimdalsrcdir)/lib/krb5/add_et_list.o \
	$(heimdalsrcdir)/lib/krb5/addr_families.o \
	$(heimdalsrcdir)/lib/krb5/appdefault.o \
	$(heimdalsrcdir)/lib/krb5/asn1_glue.o \
	$(heimdalsrcdir)/lib/krb5/auth_context.o \
	$(heimdalsrcdir)/lib/krb5/build_ap_req.o \
	$(heimdalsrcdir)/lib/krb5/build_auth.o \
	$(heimdalsrcdir)/lib/krb5/cache.o \
	$(heimdalsrcdir)/lib/krb5/changepw.o \
	$(heimdalsrcdir)/lib/krb5/codec.o \
	$(heimdalsrcdir)/lib/krb5/config_file.o \
	$(heimdalsrcdir)/lib/krb5/config_file_netinfo.o \
	$(heimdalsrcdir)/lib/krb5/constants.o \
	$(heimdalsrcdir)/lib/krb5/context.o \
	$(heimdalsrcdir)/lib/krb5/convert_creds.o \
	$(heimdalsrcdir)/lib/krb5/copy_host_realm.o \
	$(heimdalsrcdir)/lib/krb5/crc.o \
	$(heimdalsrcdir)/lib/krb5/creds.o \
	$(heimdalsrcdir)/lib/krb5/crypto.o \
	$(heimdalsrcdir)/lib/krb5/data.o \
	$(heimdalsrcdir)/lib/krb5/eai_to_heim_errno.o \
	$(heimdalsrcdir)/lib/krb5/error_string.o \
	$(heimdalsrcdir)/lib/krb5/expand_hostname.o \
	$(heimdalsrcdir)/lib/krb5/fcache.o \
	$(heimdalsrcdir)/lib/krb5/free.o \
	$(heimdalsrcdir)/lib/krb5/free_host_realm.o \
	$(heimdalsrcdir)/lib/krb5/generate_seq_number.o \
	$(heimdalsrcdir)/lib/krb5/generate_subkey.o \
	$(heimdalsrcdir)/lib/krb5/get_cred.o \
	$(heimdalsrcdir)/lib/krb5/get_default_principal.o \
	$(heimdalsrcdir)/lib/krb5/get_default_realm.o \
	$(heimdalsrcdir)/lib/krb5/get_for_creds.o \
	$(heimdalsrcdir)/lib/krb5/get_host_realm.o \
	$(heimdalsrcdir)/lib/krb5/get_in_tkt.o \
	$(heimdalsrcdir)/lib/krb5/get_in_tkt_with_keytab.o \
	$(heimdalsrcdir)/lib/krb5/get_port.o \
	$(heimdalsrcdir)/lib/krb5/init_creds.o \
	$(heimdalsrcdir)/lib/krb5/init_creds_pw.o \
	$(heimdalsrcdir)/lib/krb5/kcm.o \
	$(heimdalsrcdir)/lib/krb5/keyblock.o \
	$(heimdalsrcdir)/lib/krb5/keytab.o \
	$(heimdalsrcdir)/lib/krb5/keytab_any.o \
	$(heimdalsrcdir)/lib/krb5/keytab_file.o \
	$(heimdalsrcdir)/lib/krb5/keytab_memory.o \
	$(heimdalsrcdir)/lib/krb5/keytab_keyfile.o \
	$(heimdalsrcdir)/lib/krb5/keytab_krb4.o \
	$(heimdalsrcdir)/lib/krb5/krbhst.o \
	$(heimdalsrcdir)/lib/krb5/log.o \
	$(heimdalsrcdir)/lib/krb5/mcache.o \
	$(heimdalsrcdir)/lib/krb5/misc.o \
	$(heimdalsrcdir)/lib/krb5/mk_error.o \
	$(heimdalsrcdir)/lib/krb5/mk_priv.o \
	$(heimdalsrcdir)/lib/krb5/mk_rep.o \
	$(heimdalsrcdir)/lib/krb5/mk_req.o \
	$(heimdalsrcdir)/lib/krb5/mk_req_ext.o \
	$(heimdalsrcdir)/lib/krb5/mit_glue.o \
	$(heimdalsrcdir)/lib/krb5/n-fold.o \
	$(heimdalsrcdir)/lib/krb5/padata.o \
	$(heimdalsrcdir)/lib/krb5/pkinit.o \
	$(heimdalsrcdir)/lib/krb5/plugin.o \
	$(heimdalsrcdir)/lib/krb5/principal.o \
	$(heimdalsrcdir)/lib/krb5/pac.o \
	$(heimdalsrcdir)/lib/krb5/prompter_posix.o \
	$(heimdalsrcdir)/lib/krb5/rd_cred.o \
	$(heimdalsrcdir)/lib/krb5/rd_error.o \
	$(heimdalsrcdir)/lib/krb5/rd_priv.o \
	$(heimdalsrcdir)/lib/krb5/rd_rep.o \
	$(heimdalsrcdir)/lib/krb5/rd_req.o \
	$(heimdalsrcdir)/lib/krb5/replay.o \
	$(heimdalsrcdir)/lib/krb5/send_to_kdc.o \
	$(heimdalsrcdir)/lib/krb5/set_default_realm.o \
	$(heimdalsrcdir)/lib/krb5/store.o \
	$(heimdalsrcdir)/lib/krb5/store_emem.o \
	$(heimdalsrcdir)/lib/krb5/store_fd.o \
	$(heimdalsrcdir)/lib/krb5/store_mem.o \
	$(heimdalsrcdir)/lib/krb5/ticket.o \
	$(heimdalsrcdir)/lib/krb5/time.o \
	$(heimdalsrcdir)/lib/krb5/transited.o \
	$(heimdalsrcdir)/lib/krb5/v4_glue.o \
	$(heimdalsrcdir)/lib/krb5/version.o \
	$(heimdalsrcdir)/lib/krb5/warn.o \
	$(heimdalsrcdir)/lib/krb5/krb5_err.o \
	$(heimdalsrcdir)/lib/krb5/heim_err.o \
	$(heimdalsrcdir)/lib/krb5/k524_err.o \
	$(heimdalsrcdir)/lib/krb5/krb_err.o

#######################
# Start SUBSYSTEM HEIMDAL_HEIM_ASN1
[SUBSYSTEM::HEIMDAL_HEIM_ASN1]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/asn1
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_COM_ERR
# End SUBSYSTEM HEIMDAL_KRB5
#######################

HEIMDAL_HEIM_ASN1_OBJ_FILES = \
	$(heimdalsrcdir)/lib/asn1/der_get.o \
	$(heimdalsrcdir)/lib/asn1/der_put.o \
	$(heimdalsrcdir)/lib/asn1/der_free.o \
	$(heimdalsrcdir)/lib/asn1/der_format.o \
	$(heimdalsrcdir)/lib/asn1/der_length.o \
	$(heimdalsrcdir)/lib/asn1/der_copy.o \
	$(heimdalsrcdir)/lib/asn1/der_cmp.o \
	$(heimdalsrcdir)/lib/asn1/extra.o \
	$(heimdalsrcdir)/lib/asn1/timegm.o \
	$(heimdalsrcdir)/lib/asn1/asn1_err.o

#######################
# Start SUBSYSTEM HEIMDAL_HCRYPTO_IMATH
[SUBSYSTEM::HEIMDAL_HCRYPTO_IMATH]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/hcrypto/imath 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN 
# End SUBSYSTEM HEIMDAL_HCRYPTO_IMATH
#######################

HEIMDAL_HCRYPTO_IMATH_OBJ_FILES = \
	$(heimdalsrcdir)/lib/hcrypto/imath/imath.o \
	$(heimdalsrcdir)/lib/hcrypto/imath/iprime.o

[SUBSYSTEM::HEIMDAL_HCRYPTO]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/hcrypto -I$(heimdalsrcdir)/lib
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_HEIM_ASN1 HEIMDAL_HCRYPTO_IMATH HEIMDAL_RFC2459_ASN1
# End SUBSYSTEM HEIMDAL_HCRYPTO
#######################

HEIMDAL_HCRYPTO_OBJ_FILES = \
	$(heimdalsrcdir)/lib/hcrypto/aes.o \
	$(heimdalsrcdir)/lib/hcrypto/bn.o \
	$(heimdalsrcdir)/lib/hcrypto/dh.o \
	$(heimdalsrcdir)/lib/hcrypto/dh-imath.o \
	$(heimdalsrcdir)/lib/hcrypto/des.o \
	$(heimdalsrcdir)/lib/hcrypto/dsa.o \
	$(heimdalsrcdir)/lib/hcrypto/engine.o \
	$(heimdalsrcdir)/lib/hcrypto/md2.o \
	$(heimdalsrcdir)/lib/hcrypto/md4.o \
	$(heimdalsrcdir)/lib/hcrypto/md5.o \
	$(heimdalsrcdir)/lib/hcrypto/rsa.o \
	$(heimdalsrcdir)/lib/hcrypto/rsa-imath.o \
	$(heimdalsrcdir)/lib/hcrypto/rc2.o \
	$(heimdalsrcdir)/lib/hcrypto/rc4.o \
	$(heimdalsrcdir)/lib/hcrypto/rijndael-alg-fst.o \
	$(heimdalsrcdir)/lib/hcrypto/rnd_keys.o \
	$(heimdalsrcdir)/lib/hcrypto/sha.o \
	$(heimdalsrcdir)/lib/hcrypto/sha256.o \
	$(heimdalsrcdir)/lib/hcrypto/ui.o \
	$(heimdalsrcdir)/lib/hcrypto/evp.o \
	$(heimdalsrcdir)/lib/hcrypto/pkcs5.o \
	$(heimdalsrcdir)/lib/hcrypto/pkcs12.o \
	$(heimdalsrcdir)/lib/hcrypto/rand.o \
	$(heimdalsrcdir)/lib/hcrypto/rand-egd.o \
	$(heimdalsrcdir)/lib/hcrypto/rand-unix.o \
	$(heimdalsrcdir)/lib/hcrypto/rand-fortuna.o \
	$(heimdalsrcdir)/lib/hcrypto/rand-timer.o \
	$(heimdalsrcdir)/lib/hcrypto/hmac.o \
	$(heimdalsrcdir)/lib/hcrypto/camellia.o \
	$(heimdalsrcdir)/lib/hcrypto/camellia-ntt.o

#######################
# Start SUBSYSTEM HEIMDAL_HX509
[SUBSYSTEM::HEIMDAL_HX509]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/hx509 
PRIVATE_DEPENDENCIES = \
	HEIMDAL_ROKEN HEIMDAL_COM_ERR \
	HEIMDAL_HEIM_ASN1 HEIMDAL_HCRYPTO \
	HEIMDAL_CMS_ASN1 HEIMDAL_RFC2459_ASN1 \
	HEIMDAL_OCSP_ASN1 HEIMDAL_PKCS8_ASN1 \
	HEIMDAL_PKCS9_ASN1 HEIMDAL_PKCS12_ASN1 \
	HEIMDAL_PKINIT_ASN1 HEIMDAL_PKCS10_ASN1 \
	HEIMDAL_WIND
# End SUBSYSTEM HEIMDAL_HX509
#######################

HEIMDAL_HX509_OBJ_FILES = \
	$(heimdalsrcdir)/lib/hx509/ca.o \
	$(heimdalsrcdir)/lib/hx509/cert.o \
	$(heimdalsrcdir)/lib/hx509/cms.o \
	$(heimdalsrcdir)/lib/hx509/collector.o \
	$(heimdalsrcdir)/lib/hx509/crypto.o \
	$(heimdalsrcdir)/lib/hx509/error.o \
	$(heimdalsrcdir)/lib/hx509/env.o \
	$(heimdalsrcdir)/lib/hx509/file.o \
	$(heimdalsrcdir)/lib/hx509/keyset.o \
	$(heimdalsrcdir)/lib/hx509/ks_dir.o \
	$(heimdalsrcdir)/lib/hx509/ks_file.o \
	$(heimdalsrcdir)/lib/hx509/ks_keychain.o \
	$(heimdalsrcdir)/lib/hx509/ks_mem.o \
	$(heimdalsrcdir)/lib/hx509/ks_null.o \
	$(heimdalsrcdir)/lib/hx509/ks_p11.o \
	$(heimdalsrcdir)/lib/hx509/ks_p12.o \
	$(heimdalsrcdir)/lib/hx509/lock.o \
	$(heimdalsrcdir)/lib/hx509/name.o \
	$(heimdalsrcdir)/lib/hx509/peer.o \
	$(heimdalsrcdir)/lib/hx509/print.o \
	$(heimdalsrcdir)/lib/hx509/req.o \
	$(heimdalsrcdir)/lib/hx509/revoke.o \
	$(heimdalsrcdir)/lib/hx509/sel.o \
	$(heimdalsrcdir)/lib/hx509/sel-lex.o \
	$(heimdalsrcdir)/lib/hx509/sel-gram.o \
	$(heimdalsrcdir)/lib/hx509/hx509_err.o


#######################
# Start SUBSYSTEM HEIMDAL_WIND
[SUBSYSTEM::HEIMDAL_WIND]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/wind 
PRIVATE_DEPENDENCIES = \
	HEIMDAL_ROKEN HEIMDAL_COM_ERR

HEIMDAL_WIND_OBJ_FILES = \
	$(heimdalsrcdir)/lib/wind/wind_err.o \
	$(heimdalsrcdir)/lib/wind/stringprep.o \
	$(heimdalsrcdir)/lib/wind/errorlist.o \
	$(heimdalsrcdir)/lib/wind/errorlist_table.o \
	$(heimdalsrcdir)/lib/wind/normalize.o \
	$(heimdalsrcdir)/lib/wind/normalize_table.o \
	$(heimdalsrcdir)/lib/wind/combining.o \
	$(heimdalsrcdir)/lib/wind/combining_table.o \
	$(heimdalsrcdir)/lib/wind/utf8.o \
	$(heimdalsrcdir)/lib/wind/bidi.o \
	$(heimdalsrcdir)/lib/wind/bidi_table.o \
	$(heimdalsrcdir)/lib/wind/ldap.o \
	$(heimdalsrcdir)/lib/wind/map.o \
	$(heimdalsrcdir)/lib/wind/map_table.o
# End SUBSYSTEM HEIMDAL_WIND
#######################

[SUBSYSTEM::HEIMDAL_ROKEN_GETPROGNAME]

HEIMDAL_ROKEN_GETPROGNAME_OBJ_FILES = $(heimdalsrcdir)/lib/roken/getprogname.o
$(HEIMDAL_ROKEN_GETPROGNAME_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken  -I$(socketwrappersrcdir)

[SUBSYSTEM::HEIMDAL_ROKEN_CLOSEFROM] 

HEIMDAL_ROKEN_CLOSEFROM_OBJ_FILES = $(heimdalsrcdir)/lib/roken/closefrom.o
$(HEIMDAL_ROKEN_CLOSEFROM_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken  -I$(socketwrappersrcdir)

[SUBSYSTEM::HEIMDAL_ROKEN_GETPROGNAME_H] 

HEIMDAL_ROKEN_GETPROGNAME_H_OBJ_FILES = $(heimdalsrcdir)/lib/roken/getprogname.ho
$(HEIMDAL_ROKEN_GETPROGNAME_H_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken  -I$(socketwrappersrcdir)

#######################
# Start SUBSYSTEM HEIMDAL_ROKEN
[SUBSYSTEM::HEIMDAL_ROKEN]
CFLAGS =  -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken -I$(socketwrappersrcdir)
PRIVATE_DEPENDENCIES = \
			HEIMDAL_ROKEN_GETPROGNAME \
			HEIMDAL_ROKEN_CLOSEFROM \
			RESOLV \
			LIBREPLACE_NETWORK
# End SUBSYSTEM HEIMDAL_ROKEN
#######################

HEIMDAL_ROKEN_OBJ_FILES = \
	$(heimdalsrcdir)/lib/roken/base64.o \
	$(heimdalsrcdir)/lib/roken/hex.o \
	$(heimdalsrcdir)/lib/roken/bswap.o \
	$(heimdalsrcdir)/lib/roken/dumpdata.o \
	$(heimdalsrcdir)/lib/roken/emalloc.o \
	$(heimdalsrcdir)/lib/roken/ecalloc.o \
	$(heimdalsrcdir)/lib/roken/get_window_size.o \
	$(heimdalsrcdir)/lib/roken/h_errno.o \
	$(heimdalsrcdir)/lib/roken/issuid.o \
	$(heimdalsrcdir)/lib/roken/net_read.o \
	$(heimdalsrcdir)/lib/roken/net_write.o \
	$(heimdalsrcdir)/lib/roken/socket.o \
	$(heimdalsrcdir)/lib/roken/parse_time.o \
	$(heimdalsrcdir)/lib/roken/parse_units.o \
	$(heimdalsrcdir)/lib/roken/resolve.o \
	$(heimdalsrcdir)/lib/roken/roken_gethostby.o \
	$(heimdalsrcdir)/lib/roken/signal.o \
	$(heimdalsrcdir)/lib/roken/vis.o \
	$(heimdalsrcdir)/lib/roken/strlwr.o \
	$(heimdalsrcdir)/lib/roken/strsep_copy.o \
	$(heimdalsrcdir)/lib/roken/strsep.o \
	$(heimdalsrcdir)/lib/roken/strupr.o \
	$(heimdalsrcdir)/lib/roken/strpool.o \
	$(heimdalsrcdir)/lib/roken/estrdup.o \
	$(heimdalsrcdir)/lib/roken/erealloc.o \
	$(heimdalsrcdir)/lib/roken/simple_exec.o \
	$(heimdalsrcdir)/lib/roken/strcollect.o \
	$(heimdalsrcdir)/lib/roken/rtbl.o \
	$(heimdalsrcdir)/lib/roken/cloexec.o \
	$(heimdalsrcdir)/lib/roken/xfree.o \
	$(heimdalbuildsrcdir)/replace.o

#######################
# Start SUBSYSTEM HEIMDAL_GLUE
[SUBSYSTEM::HEIMDAL_GLUE]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/krb5 -I$(heimdalsrcdir)/lib/asn1 -I$(heimdalsrcdir)/lib/com_err 
PRIVATE_DEPENDENCIES = LIBNETIF LIBSAMBA-HOSTCONFIG
# End SUBSYSTEM HEIMDAL_GLUE
#######################

HEIMDAL_GLUE_OBJ_FILES = $(heimdalbuildsrcdir)/glue.o

#######################
# Start SUBSYSTEM HEIMDAL_COM_ERR
[SUBSYSTEM::HEIMDAL_COM_ERR]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/com_err
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN
# End SUBSYSTEM HEIMDAL_COM_ERR
#######################

HEIMDAL_COM_ERR_OBJ_FILES = \
	$(heimdalsrcdir)/lib/com_err/com_err.o \
	$(heimdalsrcdir)/lib/com_err/error.o

#######################
# Start SUBSYSTEM HEIMDAL_ASN1_COMPILE_LEX
[SUBSYSTEM::HEIMDAL_ASN1_COMPILE_LEX]
# End SUBSYSTEM HEIMDAL_ASN1_COMPILE_LEX
#######################

HEIMDAL_ASN1_COMPILE_LEX_OBJ_FILES = $(heimdalsrcdir)/lib/asn1/lex.ho 
$(HEIMDAL_ASN1_COMPILE_LEX_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/asn1 -I$(heimdalsrcdir)/lib/roken -I$(socketwrappersrcdir)

#######################
# Start BINARY asn1_compile
[BINARY::asn1_compile]
USE_HOSTCC = YES
PRIVATE_DEPENDENCIES = HEIMDAL_ASN1_COMPILE_LEX HEIMDAL_ROKEN_GETPROGNAME_H LIBREPLACE_NETWORK

ASN1C = $(builddir)/bin/asn1_compile

asn1_compile_OBJ_FILES = \
	$(heimdalsrcdir)/lib/asn1/main.ho \
	$(heimdalsrcdir)/lib/asn1/gen.ho \
	$(heimdalsrcdir)/lib/asn1/gen_copy.ho \
	$(heimdalsrcdir)/lib/asn1/gen_decode.ho \
	$(heimdalsrcdir)/lib/asn1/gen_encode.ho \
	$(heimdalsrcdir)/lib/asn1/gen_free.ho \
	$(heimdalsrcdir)/lib/asn1/gen_glue.ho \
	$(heimdalsrcdir)/lib/asn1/gen_length.ho \
	$(heimdalsrcdir)/lib/asn1/gen_seq.ho \
	$(heimdalsrcdir)/lib/asn1/hash.ho \
	$(heimdalsrcdir)/lib/asn1/parse.ho \
	$(heimdalsrcdir)/lib/roken/emalloc.ho \
	$(heimdalsrcdir)/lib/roken/getarg.ho \
	$(heimdalsrcdir)/lib/roken/setprogname.ho \
	$(heimdalsrcdir)/lib/roken/strupr.ho \
	$(heimdalsrcdir)/lib/roken/get_window_size.ho \
	$(heimdalsrcdir)/lib/roken/estrdup.ho \
	$(heimdalsrcdir)/lib/roken/ecalloc.ho \
	$(heimdalsrcdir)/lib/asn1/symbol.ho \
	$(heimdalsrcdir)/lib/vers/print_version.ho \
	$(socketwrappersrcdir)/socket_wrapper.ho \
	$(heimdalbuildsrcdir)/replace.ho

$(asn1_compile_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken -I$(heimdalsrcdir)/lib/asn1

# End BINARY asn1_compile
#######################

#######################
# Start SUBSYSTEM HEIMDAL_COM_ERR_COMPILE_LEX
[SUBSYSTEM::HEIMDAL_COM_ERR_COMPILE_LEX]
CFLAGS = -I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/com_err -I$(heimdalsrcdir)/lib/roken  -I$(socketwrappersrcdir)
# End SUBSYSTEM HEIMDAL_COM_ERR_COMPILE_LEX
#######################

HEIMDAL_COM_ERR_COMPILE_LEX_OBJ_FILES = $(heimdalsrcdir)/lib/com_err/lex.ho 

#######################
# Start BINARY compile_et
[BINARY::compile_et]
USE_HOSTCC = YES
PRIVATE_DEPENDENCIES = HEIMDAL_COM_ERR_COMPILE_LEX HEIMDAL_ROKEN_GETPROGNAME_H LIBREPLACE_NETWORK
# End BINARY compile_et
#######################

ET_COMPILER = $(builddir)/bin/compile_et

compile_et_OBJ_FILES = $(heimdalsrcdir)/lib/vers/print_version.ho \
	$(heimdalsrcdir)/lib/com_err/parse.ho \
	$(heimdalsrcdir)/lib/com_err/compile_et.ho \
	$(heimdalsrcdir)/lib/roken/getarg.ho \
	$(heimdalsrcdir)/lib/roken/get_window_size.ho \
	$(heimdalsrcdir)/lib/roken/strupr.ho \
	$(heimdalsrcdir)/lib/roken/setprogname.ho \
	$(socketwrappersrcdir)/socket_wrapper.ho \
	$(heimdalbuildsrcdir)/replace.ho

$(compile_et_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken

mkinclude perl_path_wrapper.sh asn1_deps.pl lib/hdb/hdb.asn1 hdb_asn1 \$\(heimdalsrcdir\)/lib/hdb |
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/gssapi/spnego/spnego.asn1 spnego_asn1 \$\(heimdalsrcdir\)/lib/gssapi --sequence=MechTypeList |
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/gssapi/mech/gssapi.asn1 gssapi_asn1 \$\(heimdalsrcdir\)/lib/gssapi|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/k5.asn1 krb5_asn1 \$\(heimdalsrcdir\)/lib/asn1 --encode-rfc1510-bit-string --sequence=KRB5SignedPathPrincipals --sequence=AuthorizationData --sequence=METHOD-DATA|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/digest.asn1 digest_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/pkcs8.asn1 pkcs8_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/pkcs9.asn1 pkcs9_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/pkcs12.asn1 pkcs12_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/rfc2459.asn1 rfc2459_asn1 \$\(heimdalsrcdir\)/lib/asn1 --preserve-binary=TBSCertificate --preserve-binary=TBSCRLCertList --preserve-binary=Name --sequence=GeneralNames --sequence=Extensions --sequence=CRLDistributionPoints|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/pkinit.asn1 pkinit_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/CMS.asn1 cms_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/hx509/ocsp.asn1 ocsp_asn1 \$\(heimdalsrcdir\)/lib/hx509 --preserve-binary=OCSPTBSRequest --preserve-binary=OCSPResponseData|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/asn1/kx509.asn1 kx509_asn1 \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh asn1_deps.pl lib/hx509/pkcs10.asn1 pkcs10_asn1 \$\(heimdalsrcdir\)/lib/hx509 --preserve-binary=CertificationRequestInfo|

mkinclude perl_path_wrapper.sh et_deps.pl lib/asn1/asn1_err.et \$\(heimdalsrcdir\)/lib/asn1|
mkinclude perl_path_wrapper.sh et_deps.pl lib/hdb/hdb_err.et \$\(heimdalsrcdir\)/lib/hdb|
mkinclude perl_path_wrapper.sh et_deps.pl lib/krb5/heim_err.et \$\(heimdalsrcdir\)/lib/krb5|
mkinclude perl_path_wrapper.sh et_deps.pl lib/krb5/k524_err.et \$\(heimdalsrcdir\)/lib/krb5|
mkinclude perl_path_wrapper.sh et_deps.pl lib/krb5/krb_err.et \$\(heimdalsrcdir\)/lib/krb5|
mkinclude perl_path_wrapper.sh et_deps.pl lib/krb5/krb5_err.et \$\(heimdalsrcdir\)/lib/krb5|
mkinclude perl_path_wrapper.sh et_deps.pl lib/gssapi/krb5/gkrb5_err.et \$\(heimdalsrcdir\)/lib/gssapi|
mkinclude perl_path_wrapper.sh et_deps.pl lib/hx509/hx509_err.et \$\(heimdalsrcdir\)/lib/hx509|
mkinclude perl_path_wrapper.sh et_deps.pl lib/wind/wind_err.et \$\(heimdalsrcdir\)/lib/wind|

clean::	
	@-rm -f bin/compile_et bin/asn1_compile

#######################
# Start BINARY compile_et
[BINARY::samba4kinit]
PRIVATE_DEPENDENCIES = HEIMDAL_KRB5 HEIMDAL_NTLM
# End BINARY compile_et
#######################

samba4kinit_OBJ_FILES = $(heimdalsrcdir)/kuser/kinit.o \
	$(heimdalsrcdir)/lib/vers/print_version.o \
	$(heimdalsrcdir)/lib/roken/setprogname.o \
	$(heimdalsrcdir)/lib/roken/getarg.o 

$(samba4kinit_OBJ_FILES): CFLAGS+=-I$(heimdalbuildsrcdir) -I$(heimdalsrcdir)/lib/roken

dist:: $(heimdalsrcdir)/lib/asn1/lex.c $(heimdalsrcdir)/lib/com_err/lex.c \
	$(heimdalsrcdir)/lib/asn1/parse.c $(heimdalsrcdir)/lib/com_err/parse.c \
	$(heimdalsrcdir)/lib/hx509/sel-lex.c $(heimdalsrcdir)/lib/hx509/sel-gram.c
