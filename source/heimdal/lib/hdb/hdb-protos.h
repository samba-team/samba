/* This is a generated file */
#ifndef __hdb_protos_h__
#define __hdb_protos_h__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned
HDBFlags2int (HDBFlags /*f*/);

int
copy_Event (
	const Event */*from*/,
	Event */*to*/);

int
copy_GENERATION (
	const GENERATION */*from*/,
	GENERATION */*to*/);

int
copy_HDBFlags (
	const HDBFlags */*from*/,
	HDBFlags */*to*/);

int
copy_HDB_Ext_Aliases (
	const HDB_Ext_Aliases */*from*/,
	HDB_Ext_Aliases */*to*/);

int
copy_HDB_Ext_Constrained_delegation_acl (
	const HDB_Ext_Constrained_delegation_acl */*from*/,
	HDB_Ext_Constrained_delegation_acl */*to*/);

int
copy_HDB_Ext_Lan_Manager_OWF (
	const HDB_Ext_Lan_Manager_OWF */*from*/,
	HDB_Ext_Lan_Manager_OWF */*to*/);

int
copy_HDB_Ext_PKINIT_acl (
	const HDB_Ext_PKINIT_acl */*from*/,
	HDB_Ext_PKINIT_acl */*to*/);

int
copy_HDB_Ext_PKINIT_certificate (
	const HDB_Ext_PKINIT_certificate */*from*/,
	HDB_Ext_PKINIT_certificate */*to*/);

int
copy_HDB_Ext_Password (
	const HDB_Ext_Password */*from*/,
	HDB_Ext_Password */*to*/);

int
copy_HDB_extension (
	const HDB_extension */*from*/,
	HDB_extension */*to*/);

int
copy_HDB_extensions (
	const HDB_extensions */*from*/,
	HDB_extensions */*to*/);

int
copy_Key (
	const Key */*from*/,
	Key */*to*/);

int
copy_Salt (
	const Salt */*from*/,
	Salt */*to*/);

int
copy_hdb_entry (
	const hdb_entry */*from*/,
	hdb_entry */*to*/);

int
decode_Event (
	const unsigned char */*p*/,
	size_t /*len*/,
	Event */*data*/,
	size_t */*size*/);

int
decode_GENERATION (
	const unsigned char */*p*/,
	size_t /*len*/,
	GENERATION */*data*/,
	size_t */*size*/);

int
decode_HDBFlags (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDBFlags */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_Aliases (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_Aliases */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_Constrained_delegation_acl (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_Constrained_delegation_acl */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_Lan_Manager_OWF (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_Lan_Manager_OWF */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_PKINIT_acl (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_PKINIT_acl */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_PKINIT_certificate (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_PKINIT_certificate */*data*/,
	size_t */*size*/);

int
decode_HDB_Ext_Password (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_Ext_Password */*data*/,
	size_t */*size*/);

int
decode_HDB_extension (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_extension */*data*/,
	size_t */*size*/);

int
decode_HDB_extensions (
	const unsigned char */*p*/,
	size_t /*len*/,
	HDB_extensions */*data*/,
	size_t */*size*/);

int
decode_Key (
	const unsigned char */*p*/,
	size_t /*len*/,
	Key */*data*/,
	size_t */*size*/);

int
decode_Salt (
	const unsigned char */*p*/,
	size_t /*len*/,
	Salt */*data*/,
	size_t */*size*/);

int
decode_hdb_entry (
	const unsigned char */*p*/,
	size_t /*len*/,
	hdb_entry */*data*/,
	size_t */*size*/);

int
encode_Event (
	unsigned char */*p*/,
	size_t /*len*/,
	const Event */*data*/,
	size_t */*size*/);

int
encode_GENERATION (
	unsigned char */*p*/,
	size_t /*len*/,
	const GENERATION */*data*/,
	size_t */*size*/);

int
encode_HDBFlags (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDBFlags */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_Aliases (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_Aliases */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_Constrained_delegation_acl (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_Constrained_delegation_acl */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_Lan_Manager_OWF (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_Lan_Manager_OWF */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_PKINIT_acl (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_PKINIT_acl */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_PKINIT_certificate (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_PKINIT_certificate */*data*/,
	size_t */*size*/);

int
encode_HDB_Ext_Password (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_Ext_Password */*data*/,
	size_t */*size*/);

int
encode_HDB_extension (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_extension */*data*/,
	size_t */*size*/);

int
encode_HDB_extensions (
	unsigned char */*p*/,
	size_t /*len*/,
	const HDB_extensions */*data*/,
	size_t */*size*/);

int
encode_Key (
	unsigned char */*p*/,
	size_t /*len*/,
	const Key */*data*/,
	size_t */*size*/);

int
encode_Salt (
	unsigned char */*p*/,
	size_t /*len*/,
	const Salt */*data*/,
	size_t */*size*/);

int
encode_hdb_entry (
	unsigned char */*p*/,
	size_t /*len*/,
	const hdb_entry */*data*/,
	size_t */*size*/);

void
free_Event (Event */*data*/);

void
free_GENERATION (GENERATION */*data*/);

void
free_HDBFlags (HDBFlags */*data*/);

void
free_HDB_Ext_Aliases (HDB_Ext_Aliases */*data*/);

void
free_HDB_Ext_Constrained_delegation_acl (HDB_Ext_Constrained_delegation_acl */*data*/);

void
free_HDB_Ext_Lan_Manager_OWF (HDB_Ext_Lan_Manager_OWF */*data*/);

void
free_HDB_Ext_PKINIT_acl (HDB_Ext_PKINIT_acl */*data*/);

void
free_HDB_Ext_PKINIT_certificate (HDB_Ext_PKINIT_certificate */*data*/);

void
free_HDB_Ext_Password (HDB_Ext_Password */*data*/);

void
free_HDB_extension (HDB_extension */*data*/);

void
free_HDB_extensions (HDB_extensions */*data*/);

void
free_Key (Key */*data*/);

void
free_Salt (Salt */*data*/);

void
free_hdb_entry (hdb_entry */*data*/);

krb5_error_code
hdb_add_master_key (
	krb5_context /*context*/,
	krb5_keyblock */*key*/,
	hdb_master_key */*inout*/);

krb5_error_code
hdb_check_db_format (
	krb5_context /*context*/,
	HDB */*db*/);

krb5_error_code
hdb_clear_extension (
	krb5_context /*context*/,
	hdb_entry */*entry*/,
	int /*type*/);

krb5_error_code
hdb_clear_master_key (
	krb5_context /*context*/,
	HDB */*db*/);

krb5_error_code
hdb_create (
	krb5_context /*context*/,
	HDB **/*db*/,
	const char */*filename*/);

krb5_error_code
hdb_db_create (
	krb5_context /*context*/,
	HDB **/*db*/,
	const char */*filename*/);

krb5_error_code
hdb_enctype2key (
	krb5_context /*context*/,
	hdb_entry */*e*/,
	krb5_enctype /*enctype*/,
	Key **/*key*/);

krb5_error_code
hdb_entry2string (
	krb5_context /*context*/,
	hdb_entry */*ent*/,
	char **/*str*/);

int
hdb_entry2value (
	krb5_context /*context*/,
	hdb_entry */*ent*/,
	krb5_data */*value*/);

krb5_error_code
hdb_entry_check_mandatory (
	krb5_context /*context*/,
	const hdb_entry */*ent*/);

int
hdb_entry_clear_password (
	krb5_context /*context*/,
	hdb_entry */*entry*/);

int
hdb_entry_get_password (
	krb5_context /*context*/,
	HDB */*db*/,
	const hdb_entry */*entry*/,
	char **/*p*/);

krb5_error_code
hdb_entry_get_pkinit_acl (
	const hdb_entry */*entry*/,
	const HDB_Ext_PKINIT_acl **/*a*/);

krb5_error_code
hdb_entry_get_pw_change_time (
	const hdb_entry */*entry*/,
	time_t */*t*/);

int
hdb_entry_set_password (
	krb5_context /*context*/,
	HDB */*db*/,
	hdb_entry */*entry*/,
	const char */*p*/);

krb5_error_code
hdb_entry_set_pw_change_time (
	krb5_context /*context*/,
	hdb_entry */*entry*/,
	time_t /*t*/);

HDB_extension *
hdb_find_extension (
	const hdb_entry */*entry*/,
	int /*type*/);

krb5_error_code
hdb_foreach (
	krb5_context /*context*/,
	HDB */*db*/,
	unsigned /*flags*/,
	hdb_foreach_func_t /*func*/,
	void */*data*/);

void
hdb_free_entry (
	krb5_context /*context*/,
	hdb_entry_ex */*ent*/);

void
hdb_free_key (Key */*key*/);

void
hdb_free_keys (
	krb5_context /*context*/,
	int /*len*/,
	Key */*keys*/);

void
hdb_free_master_key (
	krb5_context /*context*/,
	hdb_master_key /*mkey*/);

krb5_error_code
hdb_generate_key_set (
	krb5_context /*context*/,
	krb5_principal /*principal*/,
	Key **/*ret_key_set*/,
	size_t */*nkeyset*/,
	int /*no_salt*/);

krb5_error_code
hdb_generate_key_set_password (
	krb5_context /*context*/,
	krb5_principal /*principal*/,
	const char */*password*/,
	Key **/*keys*/,
	size_t */*num_keys*/);

krb5_error_code
hdb_init_db (
	krb5_context /*context*/,
	HDB */*db*/);

int
hdb_key2principal (
	krb5_context /*context*/,
	krb5_data */*key*/,
	krb5_principal /*p*/);

krb5_error_code
hdb_ldap_common (
	krb5_context /*context*/,
	HDB ** /*db*/,
	const char */*search_base*/,
	const char */*url*/);

krb5_error_code
hdb_ldap_create (
	krb5_context /*context*/,
	HDB ** /*db*/,
	const char */*arg*/);

krb5_error_code
hdb_ldapi_create (
	krb5_context /*context*/,
	HDB ** /*db*/,
	const char */*arg*/);

krb5_error_code
hdb_ldb_create (
	krb5_context /*context*/,
	HDB ** /*db*/,
	const char */*arg*/);

krb5_error_code
hdb_list_builtin (
	krb5_context /*context*/,
	char **/*list*/);

krb5_error_code
hdb_lock (
	int /*fd*/,
	int /*operation*/);

krb5_error_code
hdb_ndbm_create (
	krb5_context /*context*/,
	HDB **/*db*/,
	const char */*filename*/);

krb5_error_code
hdb_next_enctype2key (
	krb5_context /*context*/,
	const hdb_entry */*e*/,
	krb5_enctype /*enctype*/,
	Key **/*key*/);

int
hdb_principal2key (
	krb5_context /*context*/,
	krb5_const_principal /*p*/,
	krb5_data */*key*/);

krb5_error_code
hdb_print_entry (
	krb5_context /*context*/,
	HDB */*db*/,
	hdb_entry_ex */*entry*/,
	void */*data*/);

krb5_error_code
hdb_process_master_key (
	krb5_context /*context*/,
	int /*kvno*/,
	krb5_keyblock */*key*/,
	krb5_enctype /*etype*/,
	hdb_master_key */*mkey*/);

krb5_error_code
hdb_read_master_key (
	krb5_context /*context*/,
	const char */*filename*/,
	hdb_master_key */*mkey*/);

krb5_error_code
hdb_replace_extension (
	krb5_context /*context*/,
	hdb_entry */*entry*/,
	const HDB_extension */*ext*/);

krb5_error_code
hdb_seal_key (
	krb5_context /*context*/,
	HDB */*db*/,
	Key */*k*/);

krb5_error_code
hdb_seal_key_mkey (
	krb5_context /*context*/,
	Key */*k*/,
	hdb_master_key /*mkey*/);

krb5_error_code
hdb_seal_keys (
	krb5_context /*context*/,
	HDB */*db*/,
	hdb_entry */*ent*/);

krb5_error_code
hdb_seal_keys_mkey (
	krb5_context /*context*/,
	hdb_entry */*ent*/,
	hdb_master_key /*mkey*/);

krb5_error_code
hdb_set_master_key (
	krb5_context /*context*/,
	HDB */*db*/,
	krb5_keyblock */*key*/);

krb5_error_code
hdb_set_master_keyfile (
	krb5_context /*context*/,
	HDB */*db*/,
	const char */*keyfile*/);

krb5_error_code
hdb_unlock (int /*fd*/);

krb5_error_code
hdb_unseal_key (
	krb5_context /*context*/,
	HDB */*db*/,
	Key */*k*/);

krb5_error_code
hdb_unseal_key_mkey (
	krb5_context /*context*/,
	Key */*k*/,
	hdb_master_key /*mkey*/);

krb5_error_code
hdb_unseal_keys (
	krb5_context /*context*/,
	HDB */*db*/,
	hdb_entry */*ent*/);

krb5_error_code
hdb_unseal_keys_mkey (
	krb5_context /*context*/,
	hdb_entry */*ent*/,
	hdb_master_key /*mkey*/);

int
hdb_value2entry (
	krb5_context /*context*/,
	krb5_data */*value*/,
	hdb_entry */*ent*/);

krb5_error_code
hdb_write_master_key (
	krb5_context /*context*/,
	const char */*filename*/,
	hdb_master_key /*mkey*/);

void
initialize_hdb_error_table_r (struct et_list **/*list*/);

HDBFlags
int2HDBFlags (unsigned /*n*/);

size_t
length_Event (const Event */*data*/);

size_t
length_GENERATION (const GENERATION */*data*/);

size_t
length_HDBFlags (const HDBFlags */*data*/);

size_t
length_HDB_Ext_Aliases (const HDB_Ext_Aliases */*data*/);

size_t
length_HDB_Ext_Constrained_delegation_acl (const HDB_Ext_Constrained_delegation_acl */*data*/);

size_t
length_HDB_Ext_Lan_Manager_OWF (const HDB_Ext_Lan_Manager_OWF */*data*/);

size_t
length_HDB_Ext_PKINIT_acl (const HDB_Ext_PKINIT_acl */*data*/);

size_t
length_HDB_Ext_PKINIT_certificate (const HDB_Ext_PKINIT_certificate */*data*/);

size_t
length_HDB_Ext_Password (const HDB_Ext_Password */*data*/);

size_t
length_HDB_extension (const HDB_extension */*data*/);

size_t
length_HDB_extensions (const HDB_extensions */*data*/);

size_t
length_Key (const Key */*data*/);

size_t
length_Salt (const Salt */*data*/);

size_t
length_hdb_entry (const hdb_entry */*data*/);

#ifdef __cplusplus
}
#endif

#endif /* __hdb_protos_h__ */
