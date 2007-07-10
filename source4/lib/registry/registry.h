/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Gerald Carter                        2002.
   Copyright (C) Jelmer Vernooij					  2003-2004.
   
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

#include "core.h"
#include "talloc/talloc.h"
#include "librpc/gen_ndr/security.h"

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

/* structure to store the registry handles */
struct registry_key 
{
  const char *name;       
  const char *path;	
  const char *class_name; 
  NTTIME last_mod; 
  struct registry_hive *hive;
  void *backend_data;
};

struct registry_value 
{
  const char *name;
  unsigned int data_type;
  DATA_BLOB data;
};

/* FIXME */
typedef void (*reg_key_notification_function) (void);
typedef void (*reg_value_notification_function) (void);

/* 
 * Container for function pointers to enumeration routines
 * for virtual registry view 
 *
 * Backends can provide :
 *  - just one hive (example: nt4, w95)
 *  - several hives (example: rpc).
 * 
 * Backends should always do case-insensitive compares 
 * (everything is case-insensitive but case-preserving, 
 * just like the FS)
 *
 * There is no save function as all operations are expected to 
 * be atomic.
 */ 

struct hive_operations {
	const char *name;

	/* Implement this one */
	WERROR (*open_hive) (struct registry_hive *, struct registry_key **);

	/* Or this one */
	WERROR (*open_key) (TALLOC_CTX *, const struct registry_key *, const char *name, struct registry_key **);

	WERROR (*num_subkeys) (const struct registry_key *, uint32_t *count);
	WERROR (*num_values) (const struct registry_key *, uint32_t *count);
	WERROR (*get_subkey_by_index) (TALLOC_CTX *, const struct registry_key *, int idx, struct registry_key **);

	/* Can not contain more than one level */
	WERROR (*get_subkey_by_name) (TALLOC_CTX *, const struct registry_key *, const char *name, struct registry_key **);
	WERROR (*get_value_by_index) (TALLOC_CTX *, const struct registry_key *, int idx, struct registry_value **);

	/* Can not contain more than one level */
	WERROR (*get_value_by_name) (TALLOC_CTX *, const struct registry_key *, const char *name, struct registry_value **);

	/* Security control */
	WERROR (*key_get_sec_desc) (TALLOC_CTX *, const struct registry_key *, struct security_descriptor **);
	WERROR (*key_set_sec_desc) (const struct registry_key *, const struct security_descriptor *);

	/* Notification */
	WERROR (*request_key_change_notify) (const struct registry_key *, reg_key_notification_function);
	WERROR (*request_value_change_notify) (const struct registry_value *, reg_value_notification_function);

	/* Key management */
	WERROR (*add_key)(TALLOC_CTX *, const struct registry_key *, const char *name, uint32_t access_mask, struct security_descriptor *, struct registry_key **);
	WERROR (*del_key)(const struct registry_key *, const char *name);
	WERROR (*flush_key) (const struct registry_key *);

	/* Value management */
	WERROR (*set_value)(const struct registry_key *, const char *name, uint32_t type, const DATA_BLOB data); 
	WERROR (*del_value)(const struct registry_key *, const char *valname);
};

struct cli_credentials;

struct registry_hive
{
	const struct hive_operations *functions;
	struct registry_key *root;
	struct auth_session_info *session_info;
	struct cli_credentials *credentials;
	void *backend_data;
	const char *location;
};

/* Handle to a full registry
 * contains zero or more hives */
struct registry_context {
    void *backend_data;
	struct cli_credentials *credentials;
	struct auth_session_info *session_info;
	WERROR (*get_predefined_key) (struct registry_context *, uint32_t hkey, struct registry_key **);
};

struct reg_init_function_entry {
	const struct hive_operations *hive_functions;
	struct reg_init_function_entry *prev, *next;
};

/* Representing differences between registry files */

struct reg_diff_value
{
	const char *name;
	enum { REG_DIFF_DEL_VAL, REG_DIFF_SET_VAL } changetype;
	uint32_t type;
	DATA_BLOB data;
};

struct reg_diff_key
{
	const char *name;
	enum { REG_DIFF_CHANGE_KEY, REG_DIFF_DEL_KEY } changetype;
	uint32_t numvalues;
	struct reg_diff_value *values;
};

struct reg_diff
{
	const char *format;
	uint32_t numkeys;
	struct reg_diff_key *keys;
};

struct auth_session_info;
struct event_context;

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

_PUBLIC_ WERROR reg_open_local (TALLOC_CTX *mem_ctx, 
				struct registry_context **ctx, 
				struct auth_session_info *session_info, 
				struct cli_credentials *credentials);

_PUBLIC_ WERROR reg_open_remote(struct registry_context **ctx, 
								struct auth_session_info *session_info, 
								struct cli_credentials *credentials, 
								const char *location, struct event_context *ev);

_PUBLIC_ NTSTATUS registry_register(const void *_hive_ops);
_PUBLIC_ NTSTATUS registry_init(void);
_PUBLIC_ BOOL reg_has_backend(const char *backend);
_PUBLIC_ int reg_list_predefs(TALLOC_CTX *mem_ctx, char ***predefs, uint32_t **hkeys);
_PUBLIC_ const char *reg_get_predef_name(uint32_t hkey);
_PUBLIC_ WERROR reg_get_predefined_key_by_name(struct registry_context *ctx, const char *name, struct registry_key **key);
_PUBLIC_ WERROR reg_get_predefined_key(struct registry_context *ctx, uint32_t hkey, struct registry_key **key);
_PUBLIC_ WERROR reg_open_hive(TALLOC_CTX *parent_ctx, const char *backend, const char *location, struct auth_session_info *session_info, struct cli_credentials *credentials, struct registry_key **root);
_PUBLIC_ WERROR reg_open_key(TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, struct registry_key **result);
_PUBLIC_ WERROR reg_key_get_value_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *key, int idx, struct registry_value **val);
_PUBLIC_ WERROR reg_key_num_subkeys(const struct registry_key *key, uint32_t *count);
_PUBLIC_ WERROR reg_key_num_values(const struct registry_key *key, uint32_t *count);
_PUBLIC_ WERROR reg_key_get_subkey_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *key, int idx, struct registry_key **subkey);
WERROR reg_key_get_subkey_by_name(TALLOC_CTX *mem_ctx, const struct registry_key *key, const char *name, struct registry_key **subkey);
_PUBLIC_ WERROR reg_key_get_value_by_name(TALLOC_CTX *mem_ctx, const struct registry_key *key, const char *name, struct registry_value **val);
_PUBLIC_ WERROR reg_key_del(struct registry_key *parent, const char *name);
_PUBLIC_ WERROR reg_key_add_name(TALLOC_CTX *mem_ctx, const struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *desc, struct registry_key **newkey);
_PUBLIC_ WERROR reg_val_set(struct registry_key *key, const char *value, uint32_t type, DATA_BLOB data);
_PUBLIC_ WERROR reg_get_sec_desc(TALLOC_CTX *ctx, const struct registry_key *key, struct security_descriptor **secdesc);
_PUBLIC_ WERROR reg_del_value(const struct registry_key *key, const char *valname);
_PUBLIC_ WERROR reg_key_flush(const struct registry_key *key);
_PUBLIC_ WERROR reg_key_subkeysizes(const struct registry_key *key, uint32_t *max_subkeylen, uint32_t *max_subkeysize);
_PUBLIC_ WERROR reg_key_valuesizes(const struct registry_key *key, uint32_t *max_valnamelen, uint32_t *max_valbufsize);

/* Utility functions */

_PUBLIC_ const char *str_regtype(int type);
_PUBLIC_ char *reg_val_data_string(TALLOC_CTX *mem_ctx, uint32_t type, DATA_BLOB *data);
_PUBLIC_ char *reg_val_description(TALLOC_CTX *mem_ctx, struct registry_value *val) ;
_PUBLIC_ BOOL reg_string_to_val(TALLOC_CTX *mem_ctx, const char *type_str, const char *data_str, uint32_t *type, DATA_BLOB *data);
char *reg_path_win2unix(char *path) ;
char *reg_path_unix2win(char *path) ;
WERROR reg_open_key_abs(TALLOC_CTX *mem_ctx, struct registry_context *handle, const char *name, struct registry_key **result);
WERROR reg_key_del_abs(struct registry_context *ctx, const char *path);
WERROR reg_key_add_abs(TALLOC_CTX *mem_ctx, struct registry_context *ctx, const char *path, uint32_t access_mask, struct security_descriptor *sec_desc, struct registry_key **result);


/* Patch files */

_PUBLIC_ struct reg_diff *reg_generate_diff(TALLOC_CTX *mem_ctx, struct registry_context *ctx1, struct registry_context *ctx2);
_PUBLIC_ WERROR reg_diff_save(const struct reg_diff *diff, const char *filename);
_PUBLIC_ struct reg_diff *reg_diff_load(TALLOC_CTX *ctx, const char *fn);
_PUBLIC_ BOOL reg_diff_apply (const struct reg_diff *diff, struct registry_context *ctx);

NTSTATUS registry_rpc_init(void);

#endif /* _REGISTRY_H */
