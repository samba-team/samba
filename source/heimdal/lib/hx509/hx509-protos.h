/* This is a generated file */
#ifndef __hx509_protos_h__
#define __hx509_protos_h__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void
hx509_bitstring_print (
	const heim_bit_string */*b*/,
	hx509_vprint_func /*func*/,
	void */*ctx*/);

int
hx509_ca_sign (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	hx509_cert /*signer*/,
	hx509_cert */*certificate*/);

int
hx509_ca_sign_self (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	hx509_private_key /*signer*/,
	hx509_cert */*certificate*/);

int
hx509_ca_tbs_add_eku (
	hx509_context /*contex*/,
	hx509_ca_tbs /*tbs*/,
	const heim_oid */*oid*/);

int
hx509_ca_tbs_add_san_hostname (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const char */*dnsname*/);

int
hx509_ca_tbs_add_san_otherName (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const heim_oid */*oid*/,
	const heim_octet_string */*os*/);

int
hx509_ca_tbs_add_san_pkinit (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const char */*principal*/);

int
hx509_ca_tbs_add_san_rfc822name (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const char */*rfc822Name*/);

void
hx509_ca_tbs_free (hx509_ca_tbs */*tbs*/);

int
hx509_ca_tbs_init (
	hx509_context /*context*/,
	hx509_ca_tbs */*tbs*/);

int
hx509_ca_tbs_set_ca (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	int /*pathLenConstraint*/);

int
hx509_ca_tbs_set_notAfter (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	time_t /*t*/);

int
hx509_ca_tbs_set_notAfter_lifetime (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	time_t /*delta*/);

int
hx509_ca_tbs_set_notBefore (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	time_t /*t*/);

int
hx509_ca_tbs_set_proxy (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	int /*pathLenConstraint*/);

int
hx509_ca_tbs_set_serialnumber (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const heim_integer */*serialNumber*/);

int
hx509_ca_tbs_set_spki (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	const SubjectPublicKeyInfo */*spki*/);

int
hx509_ca_tbs_set_subject (
	hx509_context /*context*/,
	hx509_ca_tbs /*tbs*/,
	hx509_name /*subject*/);

int
hx509_cert_check_eku (
	hx509_context /*context*/,
	hx509_cert /*cert*/,
	const heim_oid */*eku*/,
	int /*allow_any_eku*/);

int
hx509_cert_cmp (
	hx509_cert /*p*/,
	hx509_cert /*q*/);

int
hx509_cert_find_subjectAltName_otherName (
	hx509_cert /*cert*/,
	const heim_oid */*oid*/,
	hx509_octet_string_list */*list*/);

void
hx509_cert_free (hx509_cert /*cert*/);

hx509_cert_attribute
hx509_cert_get_attribute (
	hx509_cert /*cert*/,
	const heim_oid */*oid*/);

int
hx509_cert_get_base_subject (
	hx509_context /*context*/,
	hx509_cert /*c*/,
	hx509_name */*name*/);

const char *
hx509_cert_get_friendly_name (hx509_cert /*cert*/);

int
hx509_cert_get_issuer (
	hx509_cert /*p*/,
	hx509_name */*name*/);

int
hx509_cert_get_serialnumber (
	hx509_cert /*p*/,
	heim_integer */*i*/);

int
hx509_cert_get_subject (
	hx509_cert /*p*/,
	hx509_name */*name*/);

int
hx509_cert_init (
	hx509_context /*context*/,
	const Certificate */*c*/,
	hx509_cert */*cert*/);

int
hx509_cert_keyusage_print (
	hx509_context /*context*/,
	hx509_cert /*c*/,
	char **/*s*/);

hx509_cert
hx509_cert_ref (hx509_cert /*cert*/);

int
hx509_cert_set_friendly_name (
	hx509_cert /*cert*/,
	const char */*name*/);

int
hx509_certs_add (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	hx509_cert /*cert*/);

int
hx509_certs_append (
	hx509_context /*context*/,
	hx509_certs /*to*/,
	hx509_lock /*lock*/,
	const char */*name*/);

int
hx509_certs_end_seq (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	hx509_cursor /*cursor*/);

int
hx509_certs_find (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	const hx509_query */*q*/,
	hx509_cert */*r*/);

void
hx509_certs_free (hx509_certs */*certs*/);

int
hx509_certs_info (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	int (*/*func*/)(void *, char *),
	void */*ctx*/);

int
hx509_certs_init (
	hx509_context /*context*/,
	const char */*name*/,
	int /*flags*/,
	hx509_lock /*lock*/,
	hx509_certs */*certs*/);

int
hx509_certs_iter (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	int (*/*fn*/)(hx509_context, void *, hx509_cert),
	void */*ctx*/);

int
hx509_certs_merge (
	hx509_context /*context*/,
	hx509_certs /*to*/,
	hx509_certs /*from*/);

int
hx509_certs_next_cert (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	hx509_cursor /*cursor*/,
	hx509_cert */*cert*/);

int
hx509_certs_start_seq (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	hx509_cursor */*cursor*/);

int
hx509_certs_store (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	int /*flags*/,
	hx509_lock /*lock*/);

int
hx509_ci_print_names (
	hx509_context /*context*/,
	void */*ctx*/,
	hx509_cert /*c*/);

void
hx509_clear_error_string (hx509_context /*context*/);

int
hx509_cms_create_signed_1 (
	hx509_context /*context*/,
	const heim_oid */*eContentType*/,
	const void */*data*/,
	size_t /*length*/,
	const AlgorithmIdentifier */*digest_alg*/,
	hx509_cert /*cert*/,
	hx509_peer_info /*peer*/,
	hx509_certs /*anchors*/,
	hx509_certs /*pool*/,
	heim_octet_string */*signed_data*/);

int
hx509_cms_decrypt_encrypted (
	hx509_context /*context*/,
	hx509_lock /*lock*/,
	const void */*data*/,
	size_t /*length*/,
	heim_oid */*contentType*/,
	heim_octet_string */*content*/);

int
hx509_cms_envelope_1 (
	hx509_context /*context*/,
	hx509_cert /*cert*/,
	const void */*data*/,
	size_t /*length*/,
	const heim_oid */*encryption_type*/,
	const heim_oid */*contentType*/,
	heim_octet_string */*content*/);

int
hx509_cms_unenvelope (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	int /*flags*/,
	const void */*data*/,
	size_t /*length*/,
	const heim_octet_string */*encryptedContent*/,
	heim_oid */*contentType*/,
	heim_octet_string */*content*/);

int
hx509_cms_unwrap_ContentInfo (
	const heim_octet_string */*in*/,
	heim_oid */*oid*/,
	heim_octet_string */*out*/,
	int */*have_data*/);

int
hx509_cms_verify_signed (
	hx509_context /*context*/,
	hx509_verify_ctx /*ctx*/,
	const void */*data*/,
	size_t /*length*/,
	hx509_certs /*store*/,
	heim_oid */*contentType*/,
	heim_octet_string */*content*/,
	hx509_certs */*signer_certs*/);

int
hx509_cms_wrap_ContentInfo (
	const heim_oid */*oid*/,
	const heim_octet_string */*buf*/,
	heim_octet_string */*res*/);

void
hx509_context_free (hx509_context */*context*/);

int
hx509_context_init (hx509_context */*context*/);

void
hx509_context_set_missing_revoke (
	hx509_context /*context*/,
	int /*flag*/);

int
hx509_crypto_available (
	hx509_context /*context*/,
	int /*type*/,
	hx509_cert /*source*/,
	AlgorithmIdentifier **/*val*/,
	unsigned int */*plen*/);

int
hx509_crypto_decrypt (
	hx509_crypto /*crypto*/,
	const void */*data*/,
	const size_t /*length*/,
	heim_octet_string */*ivec*/,
	heim_octet_string */*clear*/);

void
hx509_crypto_destroy (hx509_crypto /*crypto*/);

int
hx509_crypto_encrypt (
	hx509_crypto /*crypto*/,
	const void */*data*/,
	const size_t /*length*/,
	heim_octet_string */*ivec*/,
	heim_octet_string **/*ciphertext*/);

const heim_oid *
hx509_crypto_enctype_by_name (const char */*name*/);

void
hx509_crypto_free_algs (
	AlgorithmIdentifier */*val*/,
	unsigned int /*len*/);

int
hx509_crypto_get_params (
	hx509_context /*context*/,
	hx509_crypto /*crypto*/,
	const heim_octet_string */*ivec*/,
	heim_octet_string */*param*/);

int
hx509_crypto_init (
	hx509_context /*context*/,
	const char */*provider*/,
	const heim_oid */*enctype*/,
	hx509_crypto */*crypto*/);

const char *
hx509_crypto_provider (hx509_crypto /*crypto*/);

int
hx509_crypto_select (
	const hx509_context /*context*/,
	int /*type*/,
	const hx509_private_key /*source*/,
	hx509_peer_info /*peer*/,
	AlgorithmIdentifier */*selected*/);

int
hx509_crypto_set_key_data (
	hx509_crypto /*crypto*/,
	const void */*data*/,
	size_t /*length*/);

int
hx509_crypto_set_key_name (
	hx509_crypto /*crypto*/,
	const char */*name*/);

int
hx509_crypto_set_params (
	hx509_context /*context*/,
	hx509_crypto /*crypto*/,
	const heim_octet_string */*param*/,
	heim_octet_string */*ivec*/);

int
hx509_crypto_set_random_key (
	hx509_crypto /*crypto*/,
	heim_octet_string */*key*/);

void
hx509_err (
	hx509_context /*context*/,
	int /*exit_code*/,
	int /*error_code*/,
	char */*fmt*/,
	...);

void
hx509_free_octet_string_list (hx509_octet_string_list */*list*/);

char *
hx509_get_error_string (
	hx509_context /*context*/,
	int /*error_code*/);

int
hx509_get_one_cert (
	hx509_context /*context*/,
	hx509_certs /*certs*/,
	hx509_cert */*c*/);

int
hx509_lock_add_cert (
	hx509_context /*context*/,
	hx509_lock /*lock*/,
	hx509_cert /*cert*/);

int
hx509_lock_add_certs (
	hx509_context /*context*/,
	hx509_lock /*lock*/,
	hx509_certs /*certs*/);

int
hx509_lock_add_password (
	hx509_lock /*lock*/,
	const char */*password*/);

int
hx509_lock_command_string (
	hx509_lock /*lock*/,
	const char */*string*/);

void
hx509_lock_free (hx509_lock /*lock*/);

int
hx509_lock_init (
	hx509_context /*context*/,
	hx509_lock */*lock*/);

int
hx509_lock_prompt (
	hx509_lock /*lock*/,
	hx509_prompt */*prompt*/);

void
hx509_lock_reset_certs (
	hx509_context /*context*/,
	hx509_lock /*lock*/);

void
hx509_lock_reset_passwords (hx509_lock /*lock*/);

void
hx509_lock_reset_promper (hx509_lock /*lock*/);

int
hx509_lock_set_prompter (
	hx509_lock /*lock*/,
	hx509_prompter_fct /*prompt*/,
	void */*data*/);

int
hx509_name_copy (
	hx509_context /*context*/,
	const hx509_name /*from*/,
	hx509_name */*to*/);

void
hx509_name_free (hx509_name */*name*/);

int
hx509_name_is_null_p (const hx509_name /*name*/);

int
hx509_name_to_Name (
	const hx509_name /*from*/,
	Name */*to*/);

int
hx509_name_to_der_name (
	const hx509_name /*name*/,
	void **/*data*/,
	size_t */*length*/);

int
hx509_name_to_string (
	const hx509_name /*name*/,
	char **/*str*/);

int
hx509_ocsp_request (
	hx509_context /*context*/,
	hx509_certs /*reqcerts*/,
	hx509_certs /*pool*/,
	hx509_cert /*signer*/,
	const AlgorithmIdentifier */*digest*/,
	heim_octet_string */*request*/,
	heim_octet_string */*nonce*/);

int
hx509_ocsp_verify (
	hx509_context /*context*/,
	time_t /*now*/,
	hx509_cert /*cert*/,
	int /*flags*/,
	const void */*data*/,
	size_t /*length*/,
	time_t */*expiration*/);

void
hx509_oid_print (
	const heim_oid */*oid*/,
	hx509_vprint_func /*func*/,
	void */*ctx*/);

int
hx509_oid_sprint (
	const heim_oid */*oid*/,
	char **/*str*/);

int
hx509_parse_name (
	hx509_context /*context*/,
	const char */*str*/,
	hx509_name */*name*/);

int
hx509_peer_info_alloc (
	hx509_context /*context*/,
	hx509_peer_info */*peer*/);

int
hx509_peer_info_free (hx509_peer_info /*peer*/);

int
hx509_peer_info_set_cert (
	hx509_peer_info /*peer*/,
	hx509_cert /*cert*/);

int
hx509_peer_info_set_cms_algs (
	hx509_context /*context*/,
	hx509_peer_info /*peer*/,
	const AlgorithmIdentifier */*val*/,
	size_t /*len*/);

void
hx509_print_func (
	hx509_vprint_func /*func*/,
	void */*ctx*/,
	const char */*fmt*/,
	...);

void
hx509_print_stdout (
	void */*ctx*/,
	const char */*fmt*/,
	va_list /*va*/);

int
hx509_prompt_hidden (hx509_prompt_type /*type*/);

int
hx509_query_alloc (
	hx509_context /*context*/,
	hx509_query **/*q*/);

void
hx509_query_free (
	hx509_context /*context*/,
	hx509_query */*q*/);

int
hx509_query_match_cmp_func (
	hx509_query */*q*/,
	int (*/*func*/)(void *, hx509_cert),
	void */*ctx*/);

int
hx509_query_match_friendly_name (
	hx509_query */*q*/,
	const char */*name*/);

int
hx509_query_match_issuer_serial (
	hx509_query */*q*/,
	const Name */*issuer*/,
	const heim_integer */*serialNumber*/);

void
hx509_query_match_option (
	hx509_query */*q*/,
	hx509_query_option /*option*/);

int
hx509_revoke_add_crl (
	hx509_context /*context*/,
	hx509_revoke_ctx /*ctx*/,
	const char */*path*/);

int
hx509_revoke_add_ocsp (
	hx509_context /*context*/,
	hx509_revoke_ctx /*ctx*/,
	const char */*path*/);

void
hx509_revoke_free (hx509_revoke_ctx */*ctx*/);

int
hx509_revoke_init (
	hx509_context /*context*/,
	hx509_revoke_ctx */*ctx*/);

int
hx509_revoke_ocsp_print (
	hx509_context /*context*/,
	const char */*path*/,
	FILE */*out*/);

int
hx509_revoke_verify (
	hx509_context /*context*/,
	hx509_revoke_ctx /*ctx*/,
	hx509_certs /*certs*/,
	time_t /*now*/,
	hx509_cert /*cert*/,
	hx509_cert /*parent_cert*/);

void
hx509_set_error_string (
	hx509_context /*context*/,
	int /*flags*/,
	int /*code*/,
	const char */*fmt*/,
	...);

void
hx509_set_error_stringv (
	hx509_context /*context*/,
	int /*flags*/,
	int /*code*/,
	const char */*fmt*/,
	va_list /*ap*/);

const AlgorithmIdentifier *
hx509_signature_md2 (void);

const AlgorithmIdentifier *
hx509_signature_md5 (void);

const AlgorithmIdentifier *
hx509_signature_rsa (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_md2 (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_md5 (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_sha1 (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_sha256 (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_sha384 (void);

const AlgorithmIdentifier *
hx509_signature_rsa_with_sha512 (void);

const AlgorithmIdentifier *
hx509_signature_sha1 (void);

const AlgorithmIdentifier *
hx509_signature_sha256 (void);

const AlgorithmIdentifier *
hx509_signature_sha384 (void);

const AlgorithmIdentifier *
hx509_signature_sha512 (void);

int
hx509_unparse_der_name (
	const void */*data*/,
	size_t /*length*/,
	char **/*str*/);

int
hx509_validate_cert (
	hx509_context /*context*/,
	hx509_validate_ctx /*ctx*/,
	hx509_cert /*cert*/);

void
hx509_validate_ctx_add_flags (
	hx509_validate_ctx /*ctx*/,
	int /*flags*/);

void
hx509_validate_ctx_free (hx509_validate_ctx /*ctx*/);

int
hx509_validate_ctx_init (
	hx509_context /*context*/,
	hx509_validate_ctx */*ctx*/);

void
hx509_validate_ctx_set_print (
	hx509_validate_ctx /*ctx*/,
	hx509_vprint_func /*func*/,
	void */*c*/);

void
hx509_verify_attach_anchors (
	hx509_verify_ctx /*ctx*/,
	hx509_certs /*set*/);

void
hx509_verify_attach_revoke (
	hx509_verify_ctx /*ctx*/,
	hx509_revoke_ctx /*revoke_ctx*/);

void
hx509_verify_destroy_ctx (hx509_verify_ctx /*ctx*/);

int
hx509_verify_hostname (
	hx509_context /*context*/,
	const hx509_cert /*cert*/,
	int /*require_match*/,
	const char */*hostname*/,
	const struct sockaddr */*sa*/,
	int /*sa_size*/);

int
hx509_verify_init_ctx (
	hx509_context /*context*/,
	hx509_verify_ctx */*ctx*/);

int
hx509_verify_path (
	hx509_context /*context*/,
	hx509_verify_ctx /*ctx*/,
	hx509_cert /*cert*/,
	hx509_certs /*pool*/);

void
hx509_verify_set_proxy_certificate (
	hx509_verify_ctx /*ctx*/,
	int /*boolean*/);

void
hx509_verify_set_strict_rfc3280_verification (
	hx509_verify_ctx /*ctx*/,
	int /*boolean*/);

void
hx509_verify_set_time (
	hx509_verify_ctx /*ctx*/,
	time_t /*t*/);

int
hx509_verify_signature (
	hx509_context /*context*/,
	const hx509_cert /*signer*/,
	const AlgorithmIdentifier */*alg*/,
	const heim_octet_string */*data*/,
	const heim_octet_string */*sig*/);

#ifdef __cplusplus
}
#endif

#endif /* __hx509_protos_h__ */
