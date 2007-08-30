/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Gerald Carter                        2002.
   Copyright (C) Jelmer Vernooij					  2003-2007.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _REGISTRY_H /* _REGISTRY_H */
#define _REGISTRY_H 

struct registry_context;

#include <talloc.h>
#include "librpc/gen_ndr/security.h"
#include "lib/registry/hive.h"

/* Handles for the predefined keys */
#define HKEY_CLASSES_ROOT		 0x80000000
#define HKEY_CURRENT_USER		 0x80000001
#define HKEY_LOCAL_MACHINE		 0x80000002
#define HKEY_USERS				 0x80000003
#define HKEY_PERFORMANCE_DATA	 0x80000004
#define HKEY_CURRENT_CONFIG		 0x80000005
#define HKEY_DYN_DATA			 0x80000006
#define HKEY_PERFORMANCE_TEXT	 0x80000050
#define HKEY_PERFORMANCE_NLSTEXT 0x80000060

#define HKEY_FIRST		HKEY_CLASSES_ROOT
#define HKEY_LAST		HKEY_PERFORMANCE_NLSTEXT

struct reg_predefined_key {
	uint32_t handle;
	const char *name;
};

extern const struct reg_predefined_key reg_predefined_keys[];

#define	REG_DELETE		-1

/*
 * The general idea here is that every backend provides a 'hive'. Combining
 * various hives gives you a complete registry like windows has
 */

#define REGISTRY_INTERFACE_VERSION 1

struct reg_key_operations;

/* structure to store the registry handles */
struct registry_key 
{
	struct registry_context *context;
};

#include "lib/registry/patchfile.h"

struct registry_value 
{
  const char *name;
  unsigned int data_type;
  DATA_BLOB data;
};

/* FIXME */
typedef void (*reg_key_notification_function) (void);
typedef void (*reg_value_notification_function) (void);

struct cli_credentials;
struct registry_context;

struct registry_operations {
	const char *name;

	WERROR (*get_key_info) (TALLOC_CTX *mem_ctx,
							const struct registry_key *key,
							const char **classname,
							uint32_t *numsubkeys,
							uint32_t *numvalues,
							NTTIME *last_change_time);

	WERROR (*flush_key) (struct registry_key *key);

	WERROR (*get_predefined_key) (const struct registry_context *ctx, 
							  uint32_t key_id,
							  struct registry_key **key);

	WERROR (*open_key) (TALLOC_CTX *mem_ctx,
						struct registry_key *parent,
						const char *path,
						struct registry_key **key);

	WERROR (*create_key) (TALLOC_CTX *mem_ctx, 
						  struct registry_key *parent,
						  const char *name,
						  const char *key_class,
						  struct security_descriptor *security,
						  struct registry_key **key);

	WERROR (*delete_key) (struct registry_key *key, const char *name);

	WERROR (*delete_value) (struct registry_key *key, const char *name);

	WERROR (*enum_key) (TALLOC_CTX *mem_ctx,
						const struct registry_key *key, uint32_t idx,
						const char **name,
						const char **keyclass,
						NTTIME *last_changed_time);

	WERROR (*enum_value) (TALLOC_CTX *mem_ctx,
						  const struct registry_key *key, uint32_t idx,
						  const char **name,
						  uint32_t *type,
						  DATA_BLOB *data);

	WERROR (*get_security) (TALLOC_CTX *mem_ctx,
							const struct registry_key *key, 
							struct security_descriptor **security);

	WERROR (*set_security) (struct registry_key *key,
							const struct security_descriptor *security);

	WERROR (*load_key) (struct registry_key *key,
						const char *key_name,
						const char *path);

	WERROR (*unload_key) (struct registry_key *key, const char *name);

	WERROR (*notify_value_change) (struct registry_key *key,
									reg_value_notification_function fn);

	WERROR (*get_value) (TALLOC_CTX *mem_ctx,
						 const struct registry_key *key,
						 const char *name,
						 uint32_t *type,
						 DATA_BLOB *data);

	WERROR (*set_value) (struct registry_key *key,
						 const char *name,
						 uint32_t type,
						 const DATA_BLOB data);
}; 

/**
 * Handle to a full registry
 * contains zero or more hives 
 */
struct registry_context {
	const struct registry_operations *ops;
};

struct auth_session_info;
struct event_context;

/**
 * Open the locally defined registry.
 */
WERROR reg_open_local (TALLOC_CTX *mem_ctx, 
				struct registry_context **ctx, 
				struct auth_session_info *session_info, 
				struct cli_credentials *credentials);

WERROR reg_open_samba (TALLOC_CTX *mem_ctx,
								struct registry_context **ctx,
								struct auth_session_info *session_info,
								struct cli_credentials *credentials);

/**
 * Open the registry on a remote machine.
 */
WERROR reg_open_remote(struct registry_context **ctx, 
								struct auth_session_info *session_info, 
								struct cli_credentials *credentials, 
								const char *location, struct event_context *ev);

WERROR reg_open_wine(struct registry_context **ctx, const char *path);

const char *reg_get_predef_name(uint32_t hkey);
WERROR reg_get_predefined_key_by_name(struct registry_context *ctx, 
											   const char *name, 
											   struct registry_key **key);
WERROR reg_get_predefined_key(const struct registry_context *ctx, 
									   uint32_t hkey, 
									   struct registry_key **key);

WERROR reg_open_key(TALLOC_CTX *mem_ctx, struct registry_key *parent, 
							 const char *name, struct registry_key **result);

WERROR reg_key_get_value_by_index(TALLOC_CTX *mem_ctx, 
				   const struct registry_key *key, uint32_t idx, 
				   const char **name,
				   uint32_t *type,
				   DATA_BLOB *data);
WERROR reg_key_get_info(TALLOC_CTX *mem_ctx,
								 const struct registry_key *key, 
								 	const char **class_name,
									uint32_t *num_subkeys,
									uint32_t *num_values,
									NTTIME *last_change_time);
WERROR reg_key_get_subkey_by_index(TALLOC_CTX *mem_ctx, 
											const struct registry_key *key, 
											int idx, 
											const char **name,
											const char **classname,
											NTTIME *last_mod_time);
WERROR reg_key_get_subkey_by_name(TALLOC_CTX *mem_ctx, 
								  const struct registry_key *key, 
								  const char *name, 
								  struct registry_key **subkey);
WERROR reg_key_get_value_by_name(TALLOC_CTX *mem_ctx, 
										  const struct registry_key *key, 
										  const char *name, 
										  uint32_t *type,
										  DATA_BLOB *data);
WERROR reg_key_del(struct registry_key *parent, const char *name);
WERROR reg_key_add_name(TALLOC_CTX *mem_ctx, 
								 struct registry_key *parent, const char *name, 
								 const char *classname, 
								 struct security_descriptor *desc, 
								 struct registry_key **newkey);
WERROR reg_val_set(struct registry_key *key, const char *value, 
							uint32_t type, DATA_BLOB data);
WERROR reg_get_sec_desc(TALLOC_CTX *ctx, const struct registry_key *key, struct security_descriptor **secdesc);
WERROR reg_del_value(struct registry_key *key, const char *valname);
WERROR reg_key_flush(struct registry_key *key);
WERROR reg_create_key (TALLOC_CTX *mem_ctx, 
						struct registry_key *parent,

						  const char *name,
						  const char *key_class,
						  struct security_descriptor *security,
						  struct registry_key **key);




/* Utility functions */
const char *str_regtype(int type);
char *reg_val_data_string(TALLOC_CTX *mem_ctx, uint32_t type, 
								   const DATA_BLOB data);
char *reg_val_description(TALLOC_CTX *mem_ctx, const char *name,
								   uint32_t type, const DATA_BLOB data);
bool reg_string_to_val(TALLOC_CTX *mem_ctx, const char *type_str, const char *data_str, uint32_t *type, DATA_BLOB *data);
WERROR reg_open_key_abs(TALLOC_CTX *mem_ctx, struct registry_context *handle, const char *name, struct registry_key **result);
WERROR reg_key_del_abs(struct registry_context *ctx, const char *path);
WERROR reg_key_add_abs(TALLOC_CTX *mem_ctx, struct registry_context *ctx, const char *path, uint32_t access_mask, struct security_descriptor *sec_desc, struct registry_key **result);
WERROR reg_load_key(struct registry_context *ctx, struct registry_key *key, 
					const char *name, const char *filename);

WERROR reg_mount_hive(struct registry_context *rctx, 
					  struct hive_key *hive_key,
					  uint32_t key_id,
					  const char **elements);

struct registry_key *reg_import_hive_key(struct registry_context *ctx,
									     struct hive_key *hive, 
									     uint32_t predef_key,
										 const char **elements);
WERROR reg_get_security(TALLOC_CTX *mem_ctx, 
								 const struct registry_key *key, 
								 struct security_descriptor **security);

WERROR reg_set_security(struct registry_key *key, 
								 struct security_descriptor *security);


#endif /* _REGISTRY_H */
