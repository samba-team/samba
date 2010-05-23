#ifndef _REGISTRY_H
#define _REGISTRY_H

#include "reg_objects.h"

/* The following definitions come from registry/reg_api.c  */

WERROR reg_openhive(TALLOC_CTX *mem_ctx, const char *hive,
		    uint32 desired_access,
		    const struct nt_user_token *token,
		    struct registry_key **pkey);
WERROR reg_openkey(TALLOC_CTX *mem_ctx, struct registry_key *parent,
		   const char *name, uint32 desired_access,
		   struct registry_key **pkey);
WERROR reg_enumkey(TALLOC_CTX *mem_ctx, struct registry_key *key,
		   uint32 idx, char **name, NTTIME *last_write_time);
WERROR reg_enumvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		     uint32 idx, char **pname, struct registry_value **pval);
WERROR reg_queryvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		      const char *name, struct registry_value **pval);
WERROR reg_queryinfokey(struct registry_key *key, uint32_t *num_subkeys,
			uint32_t *max_subkeylen, uint32_t *max_subkeysize,
			uint32_t *num_values, uint32_t *max_valnamelen,
			uint32_t *max_valbufsize, uint32_t *secdescsize,
			NTTIME *last_changed_time);
WERROR reg_createkey(TALLOC_CTX *ctx, struct registry_key *parent,
		     const char *subkeypath, uint32 desired_access,
		     struct registry_key **pkey,
		     enum winreg_CreateAction *paction);
WERROR reg_deletekey(struct registry_key *parent, const char *path);
WERROR reg_setvalue(struct registry_key *key, const char *name,
		    const struct registry_value *val);
WERROR reg_deletevalue(struct registry_key *key, const char *name);
WERROR reg_getkeysecurity(TALLOC_CTX *mem_ctx, struct registry_key *key,
			  struct security_descriptor **psecdesc);
WERROR reg_setkeysecurity(struct registry_key *key,
			  struct security_descriptor *psecdesc);
WERROR reg_getversion(uint32_t *version);
WERROR reg_restorekey(struct registry_key *key, const char *fname);
WERROR reg_savekey(struct registry_key *key, const char *fname);
WERROR reg_deleteallvalues(struct registry_key *key);
WERROR reg_open_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		     uint32 desired_access, const struct nt_user_token *token,
		     struct registry_key **pkey);
WERROR reg_deletekey_recursive(TALLOC_CTX *ctx,
			       struct registry_key *parent,
			       const char *path);
WERROR reg_deletesubkeys_recursive(TALLOC_CTX *ctx,
				   struct registry_key *parent,
				   const char *path);
WERROR reg_create_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		       uint32 desired_access,
		       const struct nt_user_token *token,
		       enum winreg_CreateAction *paction,
		       struct registry_key **pkey);
WERROR reg_delete_path(const struct nt_user_token *token,
		       const char *orig_path);

/* The following definitions come from registry/reg_backend_db.c  */

WERROR init_registry_key(const char *add_path);
WERROR init_registry_data(void);
WERROR regdb_init(void);
WERROR regdb_open( void );
int regdb_close( void );
WERROR regdb_transaction_start(void);
WERROR regdb_transaction_commit(void);
WERROR regdb_transaction_cancel(void);
int regdb_get_seqnum(void);
bool regdb_store_keys(const char *key, struct regsubkey_ctr *ctr);
int regdb_fetch_keys(const char *key, struct regsubkey_ctr *ctr);
int regdb_fetch_values(const char* key, struct regval_ctr *values);
bool regdb_store_values(const char *key, struct regval_ctr *values);
bool regdb_subkeys_need_update(struct regsubkey_ctr *subkeys);
bool regdb_values_need_update(struct regval_ctr *values);

/* The following definitions come from registry/reg_dispatcher.c  */

bool store_reg_keys(struct registry_key_handle *key,
		    struct regsubkey_ctr *subkeys);
bool store_reg_values(struct registry_key_handle *key, struct regval_ctr *val);
WERROR create_reg_subkey(struct registry_key_handle *key, const char *subkey);
WERROR delete_reg_subkey(struct registry_key_handle *key, const char *subkey);
int fetch_reg_keys(struct registry_key_handle *key,
		   struct regsubkey_ctr *subkey_ctr);
int fetch_reg_values(struct registry_key_handle *key, struct regval_ctr *val);
bool regkey_access_check(struct registry_key_handle *key, uint32 requested,
			 uint32 *granted,
			 const struct nt_user_token *token);
WERROR regkey_get_secdesc(TALLOC_CTX *mem_ctx, struct registry_key_handle *key,
			  struct security_descriptor **psecdesc);
WERROR regkey_set_secdesc(struct registry_key_handle *key,
			  struct security_descriptor *psecdesc);
bool reg_subkeys_need_update(struct registry_key_handle *key,
			     struct regsubkey_ctr *subkeys);
bool reg_values_need_update(struct registry_key_handle *key,
			    struct regval_ctr *values);

/* The following definitions come from registry/reg_eventlog.c  */

bool eventlog_init_keys(void);
bool eventlog_add_source( const char *eventlog, const char *sourcename,
			  const char *messagefile );

/* The following definitions come from registry/reg_init_basic.c  */

WERROR registry_init_common(void);
WERROR registry_init_basic(void);

/* The following definitions come from registry/reg_init_full.c  */

WERROR registry_init_full(void);

/* The following definitions come from registry/reg_init_smbconf.c  */

NTSTATUS registry_create_admin_token(TALLOC_CTX *mem_ctx,
				     NT_USER_TOKEN **ptoken);
WERROR registry_init_smbconf(const char *keyname);

/* The following definitions come from registry/reg_perfcount.c  */

void perfcount_init_keys( void );
uint32 reg_perfcount_get_base_index(void);
uint32 reg_perfcount_get_last_counter(uint32 base_index);
uint32 reg_perfcount_get_last_help(uint32 last_counter);
uint32 reg_perfcount_get_counter_help(uint32 base_index, char **retbuf);
uint32 reg_perfcount_get_counter_names(uint32 base_index, char **retbuf);
WERROR reg_perfcount_get_hkpd(prs_struct *ps, uint32 max_buf_size, uint32 *outbuf_len, const char *object_ids);

/* The following definitions come from registry/reg_util.c  */

bool reg_split_path(char *path, char **base, char **new_path);
bool reg_split_key(char *path, char **base, char **key);
char *normalize_reg_path(TALLOC_CTX *ctx, const char *keyname );
void normalize_dbkey(char *key);
char *reg_remaining_path(TALLOC_CTX *ctx, const char *key);

/* The following definitions come from lib/util_reg_api.c  */

WERROR registry_pull_value(TALLOC_CTX *mem_ctx,
			   struct registry_value **pvalue,
			   enum winreg_Type type, uint8 *data,
			   uint32 size, uint32 length);
WERROR registry_push_value(TALLOC_CTX *mem_ctx,
			   const struct registry_value *value,
			   DATA_BLOB *presult);

#endif /* _REGISTRY_H */
