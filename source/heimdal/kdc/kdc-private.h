/* This is a generated file */
#ifndef __kdc_private_h__
#define __kdc_private_h__

#include <stdarg.h>

krb5_error_code
_kdc_as_rep (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	KDC_REQ */*req*/,
	const krb5_data */*req_buffer*/,
	krb5_data */*reply*/,
	const char */*from*/,
	struct sockaddr */*from_addr*/);

krb5_error_code
_kdc_check_flags (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	hdb_entry */*client*/,
	const char */*client_name*/,
	hdb_entry */*server*/,
	const char */*server_name*/,
	krb5_boolean /*is_as_req*/);

krb5_error_code
_kdc_db_fetch (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	krb5_principal /*principal*/,
	enum hdb_ent_type /*ent_type*/,
	hdb_entry_ex **/*h*/);

krb5_error_code
_kdc_db_fetch4 (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	const char */*name*/,
	const char */*instance*/,
	const char */*realm*/,
	enum hdb_ent_type /*ent_type*/,
	hdb_entry_ex **/*ent*/);

krb5_error_code
_kdc_do_524 (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	const Ticket */*t*/,
	krb5_data */*reply*/,
	const char */*from*/,
	struct sockaddr */*addr*/);

krb5_error_code
_kdc_do_kaserver (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	unsigned char */*buf*/,
	size_t /*len*/,
	krb5_data */*reply*/,
	const char */*from*/,
	struct sockaddr_in */*addr*/);

krb5_error_code
_kdc_do_version4 (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	unsigned char */*buf*/,
	size_t /*len*/,
	krb5_data */*reply*/,
	const char */*from*/,
	struct sockaddr_in */*addr*/);

krb5_error_code
_kdc_encode_v4_ticket (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	void */*buf*/,
	size_t /*len*/,
	const EncTicketPart */*et*/,
	const PrincipalName */*service*/,
	size_t */*size*/);

void
_kdc_free_ent (
	krb5_context /*context*/,
	hdb_entry_ex */*ent*/);

krb5_error_code
_kdc_get_des_key (
	krb5_context /*context*/,
	hdb_entry_ex */*principal*/,
	krb5_boolean /*is_server*/,
	krb5_boolean /*prefer_afs_key*/,
	Key **/*ret_key*/);

int
_kdc_maybe_version4 (
	unsigned char */*buf*/,
	int /*len*/);

krb5_error_code
_kdc_pk_check_client (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	krb5_principal /*client_princ*/,
	const hdb_entry_ex */*client*/,
	pk_client_params */*client_params*/,
	char **/*subject_name*/);

void
_kdc_pk_free_client_param (
	krb5_context /*context*/,
	pk_client_params */*client_params*/);

krb5_error_code
_kdc_pk_initialize (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	const char */*user_id*/,
	const char */*x509_anchors*/);

krb5_error_code
_kdc_pk_mk_pa_reply (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	pk_client_params */*client_params*/,
	const hdb_entry_ex */*client*/,
	const KDC_REQ */*req*/,
	const krb5_data */*req_buffer*/,
	krb5_keyblock **/*reply_key*/,
	METHOD_DATA */*md*/);

krb5_error_code
_kdc_pk_rd_padata (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	KDC_REQ */*req*/,
	PA_DATA */*pa*/,
	pk_client_params **/*ret_params*/);

krb5_error_code
_kdc_tgs_rep (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	KDC_REQ */*req*/,
	krb5_data */*data*/,
	const char */*from*/,
	struct sockaddr */*from_addr*/);

#endif /* __kdc_private_h__ */
