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

/* The following definitions come from registry/reg_init_basic.c  */

WERROR registry_init_common(void);
WERROR registry_init_basic(void);

/* The following definitions come from registry/reg_init_full.c  */

WERROR registry_init_full(void);

/* The following definitions come from registry/reg_init_smbconf.c  */

NTSTATUS registry_create_admin_token(TALLOC_CTX *mem_ctx,
				     NT_USER_TOKEN **ptoken);
WERROR registry_init_smbconf(const char *keyname);

/* The following definitions come from lib/util_reg_api.c  */

WERROR registry_pull_value(TALLOC_CTX *mem_ctx,
			   struct registry_value **pvalue,
			   enum winreg_Type type, uint8 *data,
			   uint32 size, uint32 length);
WERROR registry_push_value(TALLOC_CTX *mem_ctx,
			   const struct registry_value *value,
			   DATA_BLOB *presult);

#endif /* _REGISTRY_H */
