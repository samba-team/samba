/* 
   Unix SMB/CIFS implementation.
   Registry hive interface
   Copyright (C) Jelmer Vernooij					  2003-2007.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef __REGISTRY_HIVE_H__
#define __REGISTRY_HIVE_H__

#include "core.h"
#include "talloc.h"
#include "librpc/gen_ndr/security.h"

/**
 * This file contains the hive API. This API is generally used for 
 * reading a specific file that contains just one hive. 
 *
 * Good examples are .DAT (NTUSER.DAT) files.
 *
 * This API does not have any notification support (that 
 * should be provided by the registry implementation), nor 
 * does it understand what predefined keys are.
 */

struct hive_key {
	const struct hive_operations *ops;
};

struct hive_operations {
	const char *name;	

	/**
	 * Open a specific subkey
	 */
	WERROR (*enum_key) (TALLOC_CTX *mem_ctx,
						const struct hive_key *key, uint32_t idx, 
						const char **name,
						const char **classname,
						NTTIME *last_mod_time);

	/**
	 * Open a subkey by name
	 */
	WERROR (*get_key_by_name) (TALLOC_CTX *mem_ctx,
							   const struct hive_key *key, const char *name, 
							   struct hive_key **subkey);
	
	/**
	 * Add a new key.
	 */
	WERROR (*add_key) (TALLOC_CTX *ctx,
					   const struct hive_key *parent_key, const char *name, 
					   const char *classname, struct security_descriptor *desc, 
					   struct hive_key **key);
	/**
	 * Remove an existing key.
	 */
	WERROR (*del_key) (const struct hive_key *key, const char *name);

	/**
	 * Force write of a key to disk.
	 */
	WERROR (*flush_key) (struct hive_key *key);

	/**
	 * Retrieve a registry value with a specific index.
	 */
	WERROR (*enum_value) (TALLOC_CTX *mem_ctx,
						  const struct hive_key *key, int idx, 
						  const char **name, uint32_t *type, 
						  DATA_BLOB *data);

	/**
	 * Retrieve a registry value with the specified name
	 */
	WERROR (*get_value_by_name) (TALLOC_CTX *mem_ctx, 
								 struct hive_key *key, const char *name, 
								 uint32_t *type, DATA_BLOB *data);
	
	/**
	 * Set a value on the specified registry key.
	 */
	WERROR (*set_value) (struct hive_key *key, const char *name, 
						 uint32_t type, const DATA_BLOB data);

	/**
	 * Remove a value.
	 */
	WERROR (*delete_value) (struct hive_key *key, const char *name);

	/* Security Descriptors */

	/**
	 * Change the security descriptor on a registry key.
	 *
	 * This should return WERR_NOT_SUPPORTED if the underlying 
	 * format does not have a mechanism for storing 
	 * security descriptors.
	 */
	WERROR (*set_sec_desc) (struct hive_key *key, 
							const struct security_descriptor *desc);

	/**
	 * Retrieve the security descriptor on a registry key.
	 *
	 * This should return WERR_NOT_SUPPORTED if the underlying 
	 * format does not have a mechanism for storing 
	 * security descriptors.
	 */
	WERROR (*get_sec_desc) (TALLOC_CTX *ctx,
							const struct hive_key *key, 
							struct security_descriptor **desc);
	
	/**
	 * Retrieve general information about a key.
	 */
	WERROR (*get_key_info) (TALLOC_CTX *mem_ctx,
							const struct hive_key *key,
							const char **classname,
							uint32_t *num_subkeys,
							uint32_t *num_values,
							NTTIME *last_change_time);
};

struct cli_credentials;
struct auth_session_info;

WERROR reg_open_hive(TALLOC_CTX *parent_ctx, const char *location, 
							  struct auth_session_info *session_info, 
							  struct cli_credentials *credentials, 
							  struct hive_key **root);
WERROR hive_key_get_info(TALLOC_CTX *mem_ctx, const struct hive_key *key,
						 const char **classname, uint32_t *num_subkeys, 
						 uint32_t *num_values,
						 NTTIME *last_change_time);
WERROR hive_key_add_name(TALLOC_CTX *ctx, const struct hive_key *parent_key,
						 const char *name, const char *classname, struct security_descriptor *desc,
						 struct hive_key **key);
WERROR hive_key_del(const struct hive_key *key, const char *name);
WERROR hive_get_key_by_name(TALLOC_CTX *mem_ctx,
							   const struct hive_key *key, const char *name, 
							   struct hive_key **subkey);
WERROR hive_enum_key(TALLOC_CTX *mem_ctx,
					const struct hive_key *key, uint32_t idx, 
					const char **name,
					const char **classname,
					NTTIME *last_mod_time);

WERROR hive_set_value (struct hive_key *key, const char *name, 
					   uint32_t type, const DATA_BLOB data);

WERROR hive_get_value (TALLOC_CTX *mem_ctx, 
					   struct hive_key *key, const char *name, 
					   uint32_t *type, DATA_BLOB *data);
WERROR hive_get_value_by_index (TALLOC_CTX *mem_ctx, 
					   struct hive_key *key, uint32_t idx, const char **name, 
					   uint32_t *type, DATA_BLOB *data);

WERROR hive_del_value (struct hive_key *key, const char *name);

WERROR hive_key_flush(struct hive_key *key);


/* Individual backends */
WERROR reg_open_directory(TALLOC_CTX *parent_ctx, 
			const char *location, struct hive_key **key);
WERROR reg_open_regf_file(TALLOC_CTX *parent_ctx, 
						  const char *location, struct hive_key **key);
WERROR reg_open_ldb_file(TALLOC_CTX *parent_ctx, const char *location, 
								struct auth_session_info *session_info,
								struct cli_credentials *credentials,
								struct hive_key **k);


WERROR reg_create_directory(TALLOC_CTX *parent_ctx, 
			const char *location, struct hive_key **key);
WERROR reg_create_regf_file(TALLOC_CTX *parent_ctx, 
							 const char *location, 
							 int major_version, 
							 struct hive_key **key);


#endif /* __REGISTRY_HIVE_H__ */
