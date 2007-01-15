#######################
# Start SUBSYSTEM HEIMDAL_KDC
[SUBSYSTEM::HEIMDAL_KDC]
CFLAGS = -Iheimdal_build -Iheimdal/kdc
OBJ_FILES = \
	../heimdal/kdc/default_config.o \
	../heimdal/kdc/kerberos5.o \
	../heimdal/kdc/krb5tgs.o \
	../heimdal/kdc/pkinit.o \
	../heimdal/kdc/log.o \
	../heimdal/kdc/misc.o \
	../heimdal/kdc/524.o \
	../heimdal/kdc/kerberos4.o \
	../heimdal/kdc/kaserver.o \
	../heimdal/kdc/digest.o \
	../heimdal/kdc/process.o \
	../heimdal/kdc/windc.o \
	../heimdal/kdc/kx509.o \
	../heimdal/lib/asn1/asn1_KRB5SignedPath.o
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_KRB5 HEIMDAL_HDB HEIMDAL_ASN1 HEIMDAL_DES HEIMDAL_DIGEST_ASN1 HEIMDAL_KX509_ASN1 HEIMDAL_NTLM
# End SUBSYSTEM HEIMDAL_KDC
#######################

[SUBSYSTEM::HEIMDAL_NTLM]
CFLAGS = -Iheimdal_build -Iheimdal/lib/ntlm
OBJ_FILES = \
	../heimdal/lib/ntlm/ntlm.o
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_DES HEIMDAL_KRB5

[SUBSYSTEM::HEIMDAL_HDB_KEYS]
CFLAGS = -Iheimdal_build -Iheimdal/lib/hdb
OBJ_FILES = \
	../heimdal/lib/hdb/keys.o \
	../heimdal/lib/hdb/asn1_Key.o \
	../heimdal/lib/hdb/asn1_Salt.o
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_DES HEIMDAL_KRB5

#######################
# Start SUBSYSTEM HEIMDAL_HDB
[SUBSYSTEM::HEIMDAL_HDB]
CFLAGS = -Iheimdal_build -Iheimdal/lib/hdb
OBJ_FILES = \
	../heimdal/lib/hdb/db.o \
	../heimdal/lib/hdb/hdb.o \
	../heimdal/lib/hdb/ext.o \
	../heimdal/lib/hdb/keytab.o \
	../heimdal/lib/hdb/mkey.o \
	../heimdal/lib/hdb/ndbm.o \
	../heimdal/lib/hdb/hdb_err.o
PRIVATE_DEPENDENCIES = HDB_LDB HEIMDAL_HDB_KEYS HEIMDAL_ROKEN HEIMDAL_HDB_ASN1
# End SUBSYSTEM HEIMDAL_HDB
#######################

#######################
# Start SUBSYSTEM HEIMDAL_GSSAPI
[SUBSYSTEM::HEIMDAL_GSSAPI]
CFLAGS = -Iheimdal_build -Iheimdal/lib/gssapi/spnego -Iheimdal/lib/gssapi -Iheimdal/lib/gssapi/krb5 -Iheimdal/lib/gssapi/mech
OBJ_FILES = \
	../heimdal/lib/gssapi/mech/gss_krb5.o \
	../heimdal/lib/gssapi/mech/gss_mech_switch.o \
	../heimdal/lib/gssapi/mech/gss_process_context_token.o \
	../heimdal/lib/gssapi/mech/gss_buffer_set.o \
	../heimdal/lib/gssapi/mech/gss_add_cred.o \
	../heimdal/lib/gssapi/mech/gss_add_oid_set_member.o \
	../heimdal/lib/gssapi/mech/gss_compare_name.o \
	../heimdal/lib/gssapi/mech/gss_release_oid_set.o \
	../heimdal/lib/gssapi/mech/gss_create_empty_oid_set.o \
	../heimdal/lib/gssapi/mech/gss_decapsulate_token.o \
	../heimdal/lib/gssapi/mech/gss_inquire_cred_by_oid.o \
	../heimdal/lib/gssapi/mech/gss_canonicalize_name.o \
	../heimdal/lib/gssapi/mech/gss_inquire_sec_context_by_oid.o \
	../heimdal/lib/gssapi/mech/gss_inquire_names_for_mech.o \
	../heimdal/lib/gssapi/mech/gss_inquire_mechs_for_name.o \
	../heimdal/lib/gssapi/mech/gss_wrap_size_limit.o \
	../heimdal/lib/gssapi/mech/gss_names.o \
	../heimdal/lib/gssapi/mech/gss_verify.o \
	../heimdal/lib/gssapi/mech/gss_display_name.o \
	../heimdal/lib/gssapi/mech/gss_duplicate_oid.o \
	../heimdal/lib/gssapi/mech/gss_display_status.o \
	../heimdal/lib/gssapi/mech/gss_release_buffer.o \
	../heimdal/lib/gssapi/mech/gss_release_oid.o \
	../heimdal/lib/gssapi/mech/gss_test_oid_set_member.o \
	../heimdal/lib/gssapi/mech/gss_release_cred.o \
	../heimdal/lib/gssapi/mech/gss_set_sec_context_option.o \
	../heimdal/lib/gssapi/mech/gss_export_name.o \
	../heimdal/lib/gssapi/mech/gss_seal.o \
	../heimdal/lib/gssapi/mech/gss_acquire_cred.o \
	../heimdal/lib/gssapi/mech/gss_unseal.o \
	../heimdal/lib/gssapi/mech/gss_verify_mic.o \
	../heimdal/lib/gssapi/mech/gss_accept_sec_context.o \
	../heimdal/lib/gssapi/mech/gss_inquire_cred_by_mech.o \
	../heimdal/lib/gssapi/mech/gss_indicate_mechs.o \
	../heimdal/lib/gssapi/mech/gss_delete_sec_context.o \
	../heimdal/lib/gssapi/mech/gss_sign.o \
	../heimdal/lib/gssapi/mech/gss_utils.o \
	../heimdal/lib/gssapi/mech/gss_init_sec_context.o \
	../heimdal/lib/gssapi/mech/gss_oid_equal.o \
	../heimdal/lib/gssapi/mech/gss_context_time.o \
	../heimdal/lib/gssapi/mech/gss_encapsulate_token.o \
	../heimdal/lib/gssapi/mech/gss_get_mic.o \
	../heimdal/lib/gssapi/mech/gss_import_sec_context.o \
	../heimdal/lib/gssapi/mech/gss_inquire_cred.o \
	../heimdal/lib/gssapi/mech/gss_wrap.o \
	../heimdal/lib/gssapi/mech/gss_import_name.o \
	../heimdal/lib/gssapi/mech/gss_duplicate_name.o \
	../heimdal/lib/gssapi/mech/gss_unwrap.o \
	../heimdal/lib/gssapi/mech/gss_export_sec_context.o \
	../heimdal/lib/gssapi/mech/gss_inquire_context.o \
	../heimdal/lib/gssapi/mech/gss_release_name.o \
	../heimdal/lib/gssapi/mech/gss_set_cred_option.o \
	../heimdal/lib/gssapi/asn1_GSSAPIContextToken.o \
	../heimdal/lib/gssapi/spnego/init_sec_context.o \
	../heimdal/lib/gssapi/spnego/external.o \
	../heimdal/lib/gssapi/spnego/compat.o \
	../heimdal/lib/gssapi/spnego/context_stubs.o \
	../heimdal/lib/gssapi/spnego/cred_stubs.o \
	../heimdal/lib/gssapi/spnego/accept_sec_context.o \
	../heimdal/lib/gssapi/krb5/copy_ccache.o \
	../heimdal/lib/gssapi/krb5/delete_sec_context.o \
	../heimdal/lib/gssapi/krb5/init_sec_context.o \
	../heimdal/lib/gssapi/krb5/context_time.o \
	../heimdal/lib/gssapi/krb5/init.o \
	../heimdal/lib/gssapi/krb5/address_to_krb5addr.o \
	../heimdal/lib/gssapi/krb5/get_mic.o \
	../heimdal/lib/gssapi/krb5/inquire_context.o \
	../heimdal/lib/gssapi/krb5/add_cred.o \
	../heimdal/lib/gssapi/krb5/inquire_cred.o \
	../heimdal/lib/gssapi/krb5/inquire_cred_by_oid.o \
	../heimdal/lib/gssapi/krb5/inquire_cred_by_mech.o \
	../heimdal/lib/gssapi/krb5/inquire_mechs_for_name.o \
	../heimdal/lib/gssapi/krb5/inquire_names_for_mech.o \
	../heimdal/lib/gssapi/krb5/indicate_mechs.o \
	../heimdal/lib/gssapi/krb5/inquire_sec_context_by_oid.o \
	../heimdal/lib/gssapi/krb5/export_sec_context.o \
	../heimdal/lib/gssapi/krb5/import_sec_context.o \
	../heimdal/lib/gssapi/krb5/duplicate_name.o \
	../heimdal/lib/gssapi/krb5/import_name.o \
	../heimdal/lib/gssapi/krb5/compare_name.o \
	../heimdal/lib/gssapi/krb5/export_name.o \
	../heimdal/lib/gssapi/krb5/canonicalize_name.o \
	../heimdal/lib/gssapi/krb5/unwrap.o \
	../heimdal/lib/gssapi/krb5/wrap.o \
	../heimdal/lib/gssapi/krb5/release_name.o \
	../heimdal/lib/gssapi/krb5/cfx.o \
	../heimdal/lib/gssapi/krb5/add_oid_set_member.o \
	../heimdal/lib/gssapi/krb5/release_oid_set.o \
	../heimdal/lib/gssapi/krb5/create_emtpy_oid_set.o \
	../heimdal/lib/gssapi/krb5/8003.o \
	../heimdal/lib/gssapi/krb5/arcfour.o \
	../heimdal/lib/gssapi/krb5/encapsulate.o \
	../heimdal/lib/gssapi/krb5/display_name.o \
	../heimdal/lib/gssapi/krb5/sequence.o \
	../heimdal/lib/gssapi/krb5/display_status.o \
	../heimdal/lib/gssapi/krb5/release_buffer.o \
	../heimdal/lib/gssapi/krb5/test_oid_set_member.o \
	../heimdal/lib/gssapi/krb5/external.o \
	../heimdal/lib/gssapi/krb5/compat.o \
	../heimdal/lib/gssapi/krb5/acquire_cred.o \
	../heimdal/lib/gssapi/krb5/release_cred.o \
	../heimdal/lib/gssapi/krb5/set_cred_option.o \
	../heimdal/lib/gssapi/krb5/decapsulate.o \
	../heimdal/lib/gssapi/krb5/verify_mic.o \
	../heimdal/lib/gssapi/krb5/accept_sec_context.o \
	../heimdal/lib/gssapi/krb5/set_sec_context_option.o \
	../heimdal/lib/gssapi/krb5/process_context_token.o
PRIVATE_DEPENDENCIES = HEIMDAL_KRB5 HEIMDAL_ROKEN HEIMDAL_DES HEIMDAL_ASN1 HEIMDAL_GLUE HEIMDAL_SPNEGO_ASN1
# End SUBSYSTEM HEIMDAL_GSSAPI
#######################

#######################
# Start SUBSYSTEM HEIMDAL_KRB5
[SUBSYSTEM::HEIMDAL_KRB5]
CFLAGS = -Iheimdal_build -Iheimdal/lib/krb5 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_DES HEIMDAL_HX509 HEIMDAL_PKINIT_ASN1
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5_ASN1
OBJ_FILES = \
	../heimdal/lib/krb5/acache.o \
	../heimdal/lib/krb5/add_et_list.o \
	../heimdal/lib/krb5/addr_families.o \
	../heimdal/lib/krb5/appdefault.o \
	../heimdal/lib/krb5/asn1_glue.o \
	../heimdal/lib/krb5/auth_context.o \
	../heimdal/lib/krb5/build_ap_req.o \
	../heimdal/lib/krb5/build_auth.o \
	../heimdal/lib/krb5/cache.o \
	../heimdal/lib/krb5/changepw.o \
	../heimdal/lib/krb5/codec.o \
	../heimdal/lib/krb5/config_file.o \
	../heimdal/lib/krb5/config_file_netinfo.o \
	../heimdal/lib/krb5/constants.o \
	../heimdal/lib/krb5/context.o \
	../heimdal/lib/krb5/copy_host_realm.o \
	../heimdal/lib/krb5/crc.o \
	../heimdal/lib/krb5/creds.o \
	../heimdal/lib/krb5/crypto.o \
	../heimdal/lib/krb5/data.o \
	../heimdal/lib/krb5/eai_to_heim_errno.o \
	../heimdal/lib/krb5/error_string.o \
	../heimdal/lib/krb5/expand_hostname.o \
	../heimdal/lib/krb5/fcache.o \
	../heimdal/lib/krb5/free.o \
	../heimdal/lib/krb5/free_host_realm.o \
	../heimdal/lib/krb5/generate_seq_number.o \
	../heimdal/lib/krb5/generate_subkey.o \
	../heimdal/lib/krb5/get_cred.o \
	../heimdal/lib/krb5/get_default_principal.o \
	../heimdal/lib/krb5/get_default_realm.o \
	../heimdal/lib/krb5/get_for_creds.o \
	../heimdal/lib/krb5/get_host_realm.o \
	../heimdal/lib/krb5/get_in_tkt.o \
	../heimdal/lib/krb5/get_in_tkt_with_keytab.o \
	../heimdal/lib/krb5/get_port.o \
	../heimdal/lib/krb5/init_creds.o \
	../heimdal/lib/krb5/init_creds_pw.o \
	../heimdal/lib/krb5/kcm.o \
	../heimdal/lib/krb5/keyblock.o \
	../heimdal/lib/krb5/keytab.o \
	../heimdal/lib/krb5/keytab_any.o \
	../heimdal/lib/krb5/keytab_file.o \
	../heimdal/lib/krb5/keytab_memory.o \
	../heimdal/lib/krb5/keytab_keyfile.o \
	../heimdal/lib/krb5/keytab_krb4.o \
	../heimdal/lib/krb5/krbhst.o \
	../heimdal/lib/krb5/log.o \
	../heimdal/lib/krb5/mcache.o \
	../heimdal/lib/krb5/misc.o \
	../heimdal/lib/krb5/mk_error.o \
	../heimdal/lib/krb5/mk_priv.o \
	../heimdal/lib/krb5/mk_rep.o \
	../heimdal/lib/krb5/mk_req.o \
	../heimdal/lib/krb5/mk_req_ext.o \
	../heimdal/lib/krb5/mit_glue.o \
	../heimdal/lib/krb5/n-fold.o \
	../heimdal/lib/krb5/padata.o \
	../heimdal/lib/krb5/pkinit.o \
	../heimdal/lib/krb5/plugin.o \
	../heimdal/lib/krb5/principal.o \
	../heimdal/lib/krb5/pac.o \
	../heimdal/lib/krb5/rd_cred.o \
	../heimdal/lib/krb5/rd_error.o \
	../heimdal/lib/krb5/rd_priv.o \
	../heimdal/lib/krb5/rd_rep.o \
	../heimdal/lib/krb5/rd_req.o \
	../heimdal/lib/krb5/replay.o \
	../heimdal/lib/krb5/send_to_kdc.o \
	../heimdal/lib/krb5/set_default_realm.o \
	../heimdal/lib/krb5/store.o \
	../heimdal/lib/krb5/store_emem.o \
	../heimdal/lib/krb5/store_fd.o \
	../heimdal/lib/krb5/store_mem.o \
	../heimdal/lib/krb5/ticket.o \
	../heimdal/lib/krb5/time.o \
	../heimdal/lib/krb5/transited.o \
	../heimdal/lib/krb5/v4_glue.o \
	../heimdal/lib/krb5/version.o \
	../heimdal/lib/krb5/warn.o \
	../heimdal/lib/krb5/krb5_err.o \
	../heimdal/lib/krb5/heim_err.o \
	../heimdal/lib/krb5/k524_err.o
# End SUBSYSTEM HEIMDAL_KRB5
#######################

#######################
# Start SUBSYSTEM HEIMDAL_ASN1
[SUBSYSTEM::HEIMDAL_ASN1]
CFLAGS = -Iheimdal_build -Iheimdal/lib/asn1
OBJ_FILES = \
	../heimdal/lib/asn1/der_get.o \
	../heimdal/lib/asn1/der_put.o \
	../heimdal/lib/asn1/der_free.o \
	../heimdal/lib/asn1/der_format.o \
	../heimdal/lib/asn1/der_length.o \
	../heimdal/lib/asn1/der_copy.o \
	../heimdal/lib/asn1/der_cmp.o \
	../heimdal/lib/asn1/extra.o \
	../heimdal/lib/asn1/timegm.o \
	../heimdal/lib/asn1/asn1_err.o \
	../heimdal/lib/asn1/asn1_krb5int32.o \
	../heimdal/lib/asn1/asn1_krb5uint32.o
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_COM_ERR
# End SUBSYSTEM HEIMDAL_KRB5
#######################

#######################
# Start SUBSYSTEM HEIMDAL_DES_IMATH
[SUBSYSTEM::HEIMDAL_DES_IMATH]
CFLAGS = -Iheimdal_build -Iheimdal/lib/des/imath 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN 
OBJ_FILES = \
	../heimdal/lib/des/imath/imath.o \
	../heimdal/lib/des/imath/iprime.o
# End SUBSYSTEM HEIMDAL_DES_IMATH
#######################

[SUBSYSTEM::HEIMDAL_DES]
CFLAGS = -Iheimdal_build -Iheimdal/lib/des 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_ASN1 HEIMDAL_DES_IMATH HEIMDAL_RFC2459_ASN1
OBJ_FILES = \
	../heimdal/lib/des/aes.o \
	../heimdal/lib/des/bn.o \
	../heimdal/lib/des/dh.o \
	../heimdal/lib/des/dh-imath.o \
	../heimdal/lib/des/des.o \
	../heimdal/lib/des/dsa.o \
	../heimdal/lib/des/engine.o \
	../heimdal/lib/des/md2.o \
	../heimdal/lib/des/md4.o \
	../heimdal/lib/des/md5.o \
	../heimdal/lib/des/rsa.o \
	../heimdal/lib/des/rsa-imath.o \
	../heimdal/lib/des/rc2.o \
	../heimdal/lib/des/rc4.o \
	../heimdal/lib/des/rijndael-alg-fst.o \
	../heimdal/lib/des/rnd_keys.o \
	../heimdal/lib/des/sha.o \
	../heimdal/lib/des/sha256.o \
	../heimdal/lib/des/ui.o \
	../heimdal/lib/des/evp.o \
	../heimdal/lib/des/pkcs5.o \
	../heimdal/lib/des/pkcs12.o \
	../heimdal/lib/des/rand.o \
	../heimdal/lib/des/rand-unix.o \
	../heimdal/lib/des/hmac.o
# End SUBSYSTEM HEIMDAL_DES
#######################

#######################
# Start SUBSYSTEM HEIMDAL_HX509
[SUBSYSTEM::HEIMDAL_HX509]
CFLAGS = -Iheimdal_build -Iheimdal/lib/hx509 
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN HEIMDAL_ASN1 HEIMDAL_DES HEIMDAL_CMS_ASN1 HEIMDAL_RFC2459_ASN1 HEIMDAL_OCSP_ASN1 HEIMDAL_PKCS8_ASN1 HEIMDAL_PKCS9_ASN1 HEIMDAL_PKCS12_ASN1
OBJ_FILES = \
	../heimdal/lib/hx509/ca.o \
	../heimdal/lib/hx509/cert.o \
	../heimdal/lib/hx509/cms.o \
	../heimdal/lib/hx509/collector.o \
	../heimdal/lib/hx509/crypto.o \
	../heimdal/lib/hx509/error.o \
	../heimdal/lib/hx509/file.o \
	../heimdal/lib/hx509/keyset.o \
	../heimdal/lib/hx509/ks_dir.o \
	../heimdal/lib/hx509/ks_file.o \
	../heimdal/lib/hx509/ks_mem.o \
	../heimdal/lib/hx509/ks_null.o \
	../heimdal/lib/hx509/ks_p11.o \
	../heimdal/lib/hx509/ks_p12.o \
	../heimdal/lib/hx509/lock.o \
	../heimdal/lib/hx509/name.o \
	../heimdal/lib/hx509/peer.o \
	../heimdal/lib/hx509/print.o \
	../heimdal/lib/hx509/req.o \
	../heimdal/lib/hx509/revoke.o \
	../heimdal/lib/hx509/hx509_err.o
# End SUBSYSTEM HEIMDAL_HX509
#######################

#######################
# Start SUBSYSTEM HEIMDAL_ROKEN_GAI_STRERROR
[SUBSYSTEM::HEIMDAL_ROKEN_GAI_STRERROR]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/roken/gai_strerror.o

[SUBSYSTEM::HEIMDAL_ROKEN_INET_ATON]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/roken/inet_aton.o

[SUBSYSTEM::HEIMDAL_ROKEN_GETPROGNAME]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/roken/getprogname.o

[SUBSYSTEM::HEIMDAL_ROKEN_CLOSEFROM] 
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/roken/closefrom.o

[SUBSYSTEM::HEIMDAL_ROKEN_GETPROGNAME_H] 
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/roken/getprogname.ho

#######################
# Start SUBSYSTEM HEIMDAL_ROKEN_ADDRINFO
[SUBSYSTEM::HEIMDAL_ROKEN_ADDRINFO]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken
OBJ_FILES = \
	../heimdal/lib/roken/getaddrinfo.o \
	../heimdal/lib/roken/freeaddrinfo.o \
	../heimdal/lib/roken/getipnodebyaddr.o \
	../heimdal/lib/roken/getipnodebyname.o \
	../heimdal/lib/roken/freehostent.o \
	../heimdal/lib/roken/copyhostent.o \
	../heimdal/lib/roken/hostent_find_fqdn.o
PRIVATE_DEPENDENCIES = EXT_SOCKET

#######################
# Start SUBSYSTEM HEIMDAL_ROKEN
[SUBSYSTEM::HEIMDAL_ROKEN]
CFLAGS =  -Iheimdal_build -Iheimdal/lib/roken -Ilib/socket_wrapper
OBJ_FILES = \
	../heimdal/lib/roken/base64.o \
	../heimdal/lib/roken/hex.o \
	../heimdal/lib/roken/bswap.o \
	../heimdal/lib/roken/dumpdata.o \
	../heimdal/lib/roken/emalloc.o \
	../heimdal/lib/roken/get_window_size.o \
	../heimdal/lib/roken/h_errno.o \
	../heimdal/lib/roken/issuid.o \
	../heimdal/lib/roken/net_read.o \
	../heimdal/lib/roken/net_write.o \
	../heimdal/lib/roken/socket.o \
	../heimdal/lib/roken/parse_time.o \
	../heimdal/lib/roken/parse_units.o \
	../heimdal/lib/roken/resolve.o \
	../heimdal/lib/roken/roken_gethostby.o \
	../heimdal/lib/roken/signal.o \
	../heimdal/lib/roken/vis.o \
	../heimdal/lib/roken/strlwr.o \
	../heimdal/lib/roken/strsep_copy.o \
	../heimdal/lib/roken/strsep.o \
	../heimdal/lib/roken/strupr.o \
	../heimdal/lib/roken/strpool.o \
	../heimdal/lib/roken/estrdup.o \
	../heimdal/lib/roken/erealloc.o \
	../heimdal/lib/roken/simple_exec.o \
	../heimdal/lib/roken/simple_exec.o \
	../heimdal/lib/roken/strcollect.o \
	replace.o
PUBLIC_DEPENDENCIES = \
			HEIMDAL_ROKEN_ADDRINFO \
			HEIMDAL_ROKEN_GAI_STRERROR \
			HEIMDAL_ROKEN_INET_ATON \
			HEIMDAL_ROKEN_GETPROGNAME \
			HEIMDAL_ROKEN_CLOSEFROM \
			GAI \
			NSL \
			RESOLV \
			EXT_SOCKET
# End SUBSYSTEM HEIMDAL_ROKEN
#######################

#######################
# Start SUBSYSTEM HEIMDAL_GLUE
[SUBSYSTEM::HEIMDAL_GLUE]
CFLAGS = -Iheimdal_build -Iheimdal/lib/krb5 -Iheimdal/lib/asn1 -Iheimdal/lib/com_err 
OBJ_FILES = glue.o
PUBLIC_DEPENDENCIES = LIBNETIF
# End SUBSYSTEM HEIMDAL_GLUE
#######################

#######################
# Start SUBSYSTEM HEIMDAL_COM_ERR
[SUBSYSTEM::HEIMDAL_COM_ERR]
CFLAGS = -Iheimdal_build -Iheimdal/lib/com_err
OBJ_FILES = \
	../heimdal/lib/com_err/com_err.o \
	../heimdal/lib/com_err/error.o
PRIVATE_DEPENDENCIES = HEIMDAL_ROKEN
# End SUBSYSTEM HEIMDAL_COM_ERR
#######################

#######################
# Start SUBSYSTEM HEIMDAL_ASN1_COMPILE_LEX
[SUBSYSTEM::HEIMDAL_ASN1_COMPILE_LEX]
CFLAGS = -Iheimdal_build -Iheimdal/lib/asn1 -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/asn1/lex.ho 
# End SUBSYSTEM HEIMDAL_ASN1_COMPILE_LEX
#######################

#######################
# Start BINARY asn1_compile
[BINARY::asn1_compile]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken
USE_HOSTCC = YES
OBJ_FILES = \
	../heimdal/lib/asn1/main.ho \
	../heimdal/lib/asn1/gen.ho \
	../heimdal/lib/asn1/gen_copy.ho \
	../heimdal/lib/asn1/gen_decode.ho \
	../heimdal/lib/asn1/gen_encode.ho \
	../heimdal/lib/asn1/gen_free.ho \
	../heimdal/lib/asn1/gen_glue.ho \
	../heimdal/lib/asn1/gen_length.ho \
	../heimdal/lib/asn1/gen_seq.ho \
	../heimdal/lib/asn1/hash.ho \
	../heimdal/lib/asn1/parse.ho \
	../heimdal/lib/roken/emalloc.ho \
	../heimdal/lib/roken/getarg.ho \
	../heimdal/lib/roken/setprogname.ho \
	../heimdal/lib/roken/strupr.ho \
	../heimdal/lib/roken/get_window_size.ho \
	../heimdal/lib/roken/estrdup.ho \
	../heimdal/lib/roken/ecalloc.ho \
	../heimdal/lib/asn1/symbol.ho \
	../heimdal/lib/vers/print_version.ho \
	replace.ho
PRIVATE_DEPENDENCIES = HEIMDAL_ASN1_COMPILE_LEX HEIMDAL_ROKEN_GETPROGNAME_H
# End BINARY asn1_compile
#######################

#######################
# Start SUBSYSTEM HEIMDAL_COM_ERR_COMPILE_LEX
[SUBSYSTEM::HEIMDAL_COM_ERR_COMPILE_LEX]
CFLAGS = -Iheimdal_build -Iheimdal/lib/com_err -Iheimdal/lib/roken  -Ilib/socket_wrapper
OBJ_FILES = ../heimdal/lib/com_err/lex.ho 
# End SUBSYSTEM HEIMDAL_COM_ERR_COMPILE_LEX
#######################

#######################
# Start BINARY compile_et
[BINARY::compile_et]
CFLAGS = -Iheimdal_build -Iheimdal/lib/roken
USE_HOSTCC = YES
OBJ_FILES = ../heimdal/lib/vers/print_version.ho \
	../heimdal/lib/com_err/parse.ho \
	../heimdal/lib/com_err/compile_et.ho \
	../heimdal/lib/roken/getarg.ho \
	../heimdal/lib/roken/get_window_size.ho \
	../heimdal/lib/roken/strupr.ho \
	../heimdal/lib/roken/setprogname.ho \
	replace.ho
PRIVATE_DEPENDENCIES = HEIMDAL_COM_ERR_COMPILE_LEX HEIMDAL_ROKEN_GETPROGNAME_H
# End BINARY compile_et
#######################

include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/hdb/hdb.asn1 hdb_asn1 heimdal/lib/hdb |
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/gssapi/spnego/spnego.asn1 spnego_asn1 heimdal/lib/gssapi --sequence=MechTypeList |
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/gssapi/mech/gssapi.asn1 gssapi_asn1 heimdal/lib/gssapi|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/k5.asn1 krb5_asn1 heimdal/lib/asn1 --encode-rfc1510-bit-string --sequence=KRB5SignedPathPrincipals --sequence=AuthorizationData|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/digest.asn1 digest_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/pkcs8.asn1 pkcs8_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/pkcs9.asn1 pkcs9_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/pkcs12.asn1 pkcs12_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/rfc2459.asn1 rfc2459_asn1 heimdal/lib/asn1 --preserve-binary=TBSCertificate --preserve-binary=TBSCRLCertList --preserve-binary=Name --sequence=GeneralNames --sequence=Extensions|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/pkinit.asn1 pkinit_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/CMS.asn1 cms_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/hx509/ocsp.asn1 ocsp_asn1 heimdal/lib/hx509 --preserve-binary=OCSPTBSRequest --preserve-binary=OCSPResponseData|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/asn1/kx509.asn1 kx509_asn1 heimdal/lib/asn1|
include perl_path_wrapper.sh asn1_deps.pl heimdal/lib/hx509/pkcs10.asn1 pkcs10_asn1 heimdal/lib/hx509 --preserve-binary=CertificationRequestInfo|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/asn1/asn1_err.et heimdal/lib/asn1|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/hdb/hdb_err.et heimdal/lib/hdb|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/krb5/heim_err.et heimdal/lib/krb5|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/krb5/k524_err.et heimdal/lib/krb5|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/krb5/krb5_err.et heimdal/lib/krb5|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/gssapi/krb5/gkrb5_err.et heimdal/lib/gssapi|
include perl_path_wrapper.sh et_deps.pl heimdal/lib/hx509/hx509_err.et heimdal/lib/hx509|

.SUFFIXES: .hin 
.hin.h:
	@cp $< $@

heimdal/lib/roken/vis.h: heimdal/lib/roken/vis.hin
heimdal/lib/roken/err.h: heimdal/lib/roken/err.hin

include perl_path_wrapper.sh hcrypto-deps.pl heimdal/lib/des/*.h|

heimdal/lib/des/hcrypto: 
	@rm -f $@; ln -s ./../des $@

clean::	
	@-rm -f heimdal/lib/roken/vis.h heimdal/lib/roken/err.h
	@-rm -f bin/compile_et bin/asn1_compile
	@-rm -f heimdal/lib/krb5/des/hcrypto

#######################
# Start SUBSYSTEM HEIMDAL
[LIBRARY::HEIMDAL]
VERSION = 0.0.1
SO_VERSION = 0
CFLAGS = -Iheimdal_build
OBJ_FILES = ../heimdal/lib/vers/print_version.o
PUBLIC_DEPENDENCIES = \
		HEIMDAL_GSSAPI HEIMDAL_KRB5
# End SUBSYSTEM HEIMDAL
#######################

#######################
# Start SUBSYSTEM KERBEROS_LIB
[SUBSYSTEM::KERBEROS_LIB]
#PUBLIC_DEPENDENCIES = EXT_KRB5
PUBLIC_DEPENDENCIES = HEIMDAL
# End SUBSYSTEM KERBEROS_LIB
#######################

dist:: heimdal/lib/asn1/lex.c heimdal/lib/com_err/lex.c \
	heimdal/lib/asn1/parse.c heimdal/lib/com_err/parse.c
