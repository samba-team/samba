/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _REGEDIT_H_
#define _REGEDIT_H_

struct registry_context;
struct security_token;
struct registry_key;

struct samba3_registry_key {
	struct registry_key *key;
};

WERROR reg_openhive_wrap(TALLOC_CTX *ctx, const char *hive,
			 struct samba3_registry_key *key);
WERROR reg_openkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *parent,
		        const char *name, struct samba3_registry_key *key);
WERROR reg_enumvalue_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			  uint32_t idx, char **name, uint32_t *type,
			  DATA_BLOB *data);
WERROR reg_queryvalue_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			   const char *name, uint32_t *type, DATA_BLOB *data);
WERROR reg_enumkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			uint32_t idx, char **name, NTTIME *last_write_time);
WERROR reg_createkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *parent,
			  const char *subkeypath,
			  struct samba3_registry_key *pkey);
WERROR reg_deletekey_wrap(struct samba3_registry_key *parent,
			  const char *path);
WERROR reg_deletevalue_wrap(struct samba3_registry_key *key, const char *name);
WERROR reg_queryinfokey_wrap(struct samba3_registry_key *key,
			     uint32_t *num_subkeys, uint32_t *max_subkeylen,
			     uint32_t *max_subkeysize, uint32_t *num_values,
			     uint32_t *max_valnamelen,
			     uint32_t *max_valbufsize, uint32_t *secdescsize,
			     NTTIME *last_changed_time);
WERROR reg_setvalue_wrap(struct samba3_registry_key *key, const char *name,
			 uint32_t type, const DATA_BLOB data);
WERROR reg_init_wrap(void);

WERROR reg_open_samba3(TALLOC_CTX *mem_ctx, struct registry_context **ctx);

int regedit_getch(void);

typedef bool (*regedit_search_match_fn_t)(const char *, const char *);

struct regedit_search_opts {
	const char *query;
	regedit_search_match_fn_t match;
	bool search_key;
	bool search_value;
	bool search_recursive;
	bool search_case;
};

#define PAIR_YELLOW_CYAN 1
#define PAIR_BLACK_CYAN 2
#define PAIR_YELLOW_BLUE 3

#endif
