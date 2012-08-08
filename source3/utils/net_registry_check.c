/*
 * Samba Unix/Linux SMB client library
 *
 * Copyright (C) Gregor Beck 2011
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

/**
 * @brief  Check the registry database.
 * @author Gregor Beck <gb@sernet.de>
 * @date   Mar 2011
 */

#include "net_registry_check.h"

#include "includes.h"
#include "system/filesys.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "net.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/secdesc.h"
#include "cbuf.h"
#include "srprs.h"
#include <termios.h>
#include "util_tdb.h"
#include "registry/reg_db.h"
#include "libcli/registry/util_reg.h"
#include "registry/reg_parse_internal.h"
#include "interact.h"

/*
  check tree:
  + every key has a subkeylist
  + every key is referenced by the subkeylist of its parent
  check path:
  + starts with valid hive
  + UTF-8 (option to convert ???)
  + only uppercase
  + separator ???
  check value:
  + REG_DWORD has size 4
  + REG_QWORD has size 8
  + STRINGS are zero terminated UTF-16
*/

struct regval {
	char *name;
	uint32_t type;
	DATA_BLOB data;
};

struct regkey {
	char *name;
	char *path;
	bool has_subkeylist;
	bool needs_update;
	struct regkey *parent;
	size_t nsubkeys;
	struct regkey **subkeys;
	size_t nvalues;
	struct regval **values;
	struct security_descriptor *sd;
};

struct check_ctx {
	char *fname;
	struct check_options opt;

	uint32_t version;
	char sep;
	struct db_context *idb;
	struct db_context *odb;

	struct regkey *root; /*dummy key to hold all basekeys*/
	struct db_context *reg;
	struct db_context *del;

	bool transaction;
	char auto_action;
	char default_action;
};

static void* talloc_array_append(void *mem_ctx, void* array[], void *ptr)
{
	size_t size = array ? talloc_array_length(array) : 1;
	void **tmp = talloc_realloc(mem_ctx, array, void*, size + 1);
	if (tmp == NULL) {
		talloc_free(array);
		return NULL;
	}
	tmp[size-1] = ptr;
	tmp[size] = NULL;
	return tmp;
}

static void regkey_add_subkey(struct regkey *key, struct regkey *subkey)
{
	key->subkeys = (struct regkey**)
		talloc_array_append(key, (void**)key->subkeys, subkey);
	if (key->subkeys != NULL) {
		key->nsubkeys++;
	}
}

static struct regval* regval_copy(TALLOC_CTX *mem_ctx, const struct regval *val)
{
	struct regval *ret = talloc_zero(mem_ctx, struct regval);
	if (ret == NULL) {
		goto fail;
	}

	ret->name = talloc_strdup(ret, val->name);
	if (ret->name == NULL) {
		goto fail;
	}

	ret->data = data_blob_dup_talloc(ret, val->data);
	if (ret->data.data == NULL) {
		goto fail;
	}

	ret->type = val->type;

	return ret;
fail:
	talloc_free(ret);
	return NULL;
}

static void regkey_add_regval(struct regkey *key, struct regval *val)
{
	key->values = (struct regval**)
		talloc_array_append(key, (void**)key->values, val);
	if (key->values != NULL) {
		key->nvalues++;
	}
}

static bool tdb_data_read_uint32(TDB_DATA *buf, uint32_t *result)
{
	const size_t len = sizeof(uint32_t);
	if (buf->dsize >= len) {
		*result = IVAL(buf->dptr, 0);
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_read_cstr(TDB_DATA *buf, char **result)
{
	const size_t len = strnlen((char*)buf->dptr, buf->dsize) + 1;
	if (buf->dsize >= len) {
		*result = (char*)buf->dptr;
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_read_blob(TDB_DATA *buf, DATA_BLOB *result)
{
	TDB_DATA tmp = *buf;
	uint32_t len;
	if (!tdb_data_read_uint32(&tmp, &len)) {
		return false;
	}
	if (tmp.dsize >= len) {
		*buf = tmp;
		result->data   = tmp.dptr;
		result->length = len;
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_read_regval(TDB_DATA *buf, struct regval *result)
{
	TDB_DATA tmp = *buf;
	struct regval value;
	if (!tdb_data_read_cstr(&tmp, &value.name)
	    || !tdb_data_read_uint32(&tmp, &value.type)
	    || !tdb_data_read_blob(&tmp, &value.data))
	{
		return false;
	}
	*buf = tmp;
	*result = value;
	return true;
}

static bool tdb_data_is_cstr(TDB_DATA d) {
	if (tdb_data_is_empty(d) || (d.dptr[d.dsize-1] != '\0')) {
		return false;
	}
	return strlen((char *)d.dptr) == d.dsize-1;
}

static char* tdb_data_print(TALLOC_CTX *mem_ctx, TDB_DATA d)
{
	if (!tdb_data_is_empty(d)) {
		char *ret = NULL;
		cbuf *ost = cbuf_new(mem_ctx);
		int len = cbuf_print_quoted(ost, (const char*)d.dptr, d.dsize);
		if (len != -1) {
			cbuf_swapptr(ost, &ret, 0);
			talloc_steal(mem_ctx, ret);
		}
		talloc_free(ost);
		return ret;
	}
	return talloc_strdup(mem_ctx, "<NULL>");
}


static TDB_DATA cbuf_make_tdb_data(cbuf *b)
{
	return make_tdb_data((void*)cbuf_gets(b, 0), cbuf_getpos(b));
}

static void remove_all(char *str, char c)
{
	char *out=str;
	while (*str) {
		if (*str != c) {
			*out = *str;
			out++;
		}
		str++;
	}
	*out = '\0';
}

static char* parent_path(const char *path, char sep)
{
	const char *p = strrchr(path, sep);
	return p ? talloc_strndup(talloc_tos(), path, p-path) : NULL;
}

/* return the regkey corresponding to path, create if not yet existing */
static struct regkey*
check_ctx_lookup_key(struct check_ctx *ctx, const char *path) {
	struct regkey *ret = NULL;
	NTSTATUS status;
	TDB_DATA val = tdb_null;

	if ( path == NULL) {
		return ctx->root;
	}

	status = dbwrap_fetch(ctx->reg, ctx, string_term_tdb_data(path), &val);
	if (NT_STATUS_IS_OK(status)) {
		if (ctx->opt.verbose) {
			printf("Open: %s\n", path);
		}
		ret = *(struct regkey**)val.dptr;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/* not yet existing, create */
		char *pp;
		if (ctx->opt.verbose) {
			printf("New: %s\n", path);
		}
		ret = talloc_zero(ctx, struct regkey);
		if (ret == NULL) {
			DEBUG(0, ("Out of memory!\n"));
			goto done;
		}
		ret->path = talloc_strdup(ret, path);

		pp = parent_path(path, ctx->sep);
		ret->parent = check_ctx_lookup_key(ctx, pp);
		regkey_add_subkey(ret->parent, ret);
		TALLOC_FREE(pp);

		/* the dummy root key has no subkeylist so set the name */
		if (ret->parent == ctx->root) {
			ret->name = talloc_strdup(ret, path);
		}

		dbwrap_store(ctx->reg, string_term_tdb_data(path),
			     make_tdb_data((void*)&ret, sizeof(ret)), 0);
	} else {
		DEBUG(0, ("lookup key: failed to fetch %s: %s\n", path,
			  nt_errstr(status)));
	}
done:
	talloc_free(val.dptr);
	return ret;
}

static struct check_ctx* check_ctx_create(TALLOC_CTX *mem_ctx, const char *db,
					  const struct check_options *opt)
{
	struct check_ctx *ctx = talloc_zero(mem_ctx, struct check_ctx);

	ctx->opt = *opt;
	ctx->reg = db_open_rbt(ctx);
	ctx->del = db_open_rbt(ctx);
	ctx->root = talloc_zero(ctx, struct regkey);
	ctx->fname = talloc_strdup(ctx, db);

	if (opt->automatic && (opt->output == NULL)) {
		ctx->opt.repair = true;
		ctx->opt.output = ctx->fname;
	}

	if (opt->repair) {
		if (opt->output) {
			d_fprintf(stderr, "You can not specify --output "
				  "with --repair\n");
			goto fail;
		} else {
			ctx->opt.output = ctx->fname;
		}
	}

	ctx->default_action = 'r';
	return ctx;
fail:
	talloc_free(ctx);
	return NULL;
}

static bool check_ctx_open_output(struct check_ctx *ctx)
{
	int oflags = O_RDWR | O_CREAT ;

	if (ctx->opt.output == NULL) {
		return true;
	}

	if (!ctx->opt.repair) {
		if (!ctx->opt.wipe) {
			oflags |= O_EXCL;
		}
		ctx->opt.wipe = true;
	}

	ctx->odb = db_open(ctx, ctx->opt.output, 0, TDB_DEFAULT, oflags, 0644,
			   DBWRAP_LOCK_ORDER_1);
	if (ctx->odb == NULL) {
		d_fprintf(stderr,
			  _("Could not open db (%s) for writing: %s\n"),
			  ctx->opt.output, strerror(errno));
		return false;
	}
	return true;
}


static bool check_ctx_open_input(struct check_ctx *ctx) {
	ctx->idb = db_open(ctx, ctx->fname, 0, TDB_DEFAULT, O_RDONLY, 0,
			   DBWRAP_LOCK_ORDER_1);
	if (ctx->idb == NULL) {
		d_fprintf(stderr,
			  _("Could not open db (%s) for reading: %s\n"),
			  ctx->fname, strerror(errno));
		return false;
	}
	return true;
}

static bool check_ctx_transaction_start(struct check_ctx *ctx) {
	if (ctx->odb == NULL) {
		return true;
	}
	if (dbwrap_transaction_start(ctx->odb) != 0) {
		DEBUG(0, ("transaction_start failed\n"));
		return false;
	}
	ctx->transaction = true;
	return true;
}

static void check_ctx_transaction_stop(struct check_ctx *ctx, bool ok) {
	if (!ctx->transaction) {
		return;
	}
	if (!ctx->opt.test && ok) {
		d_printf("Commiting changes\n");
		if (dbwrap_transaction_commit(ctx->odb) != 0) {
			DEBUG(0, ("transaction_commit failed\n"));
		}
	} else {
		d_printf("Discarding changes\n");
		dbwrap_transaction_cancel(ctx->odb);
	}
}

static bool read_info(struct check_ctx *ctx, const char *key, TDB_DATA val)
{
	if (val.dsize==sizeof(uint32_t) && strcmp(key, "version")==0) {
		uint32_t v = IVAL(val.dptr, 0);
		printf("INFO: %s = %d\n", key, v);
		return true;
	}
	printf("INFO: %s = <invalid>\n", key);
	return false;
}

static bool is_all_upper(const char *str) {
	bool ret;
	char *tmp = talloc_strdup(talloc_tos(), str);
	if (!strupper_m(tmp)) {
		talloc_free(tmp);
		return false;
	}
	ret = (strcmp(tmp, str) == 0);
	talloc_free(tmp);
	return ret;
}

static void move_to_back(struct regkey *key, struct regkey *subkey)
{
	struct regkey **ptr;
	size_t nidx;

	DEBUG(5, ("Move to back subkey \"%s\" of \"%s\"\n",
		  subkey->path, key->path));

	for (ptr=key->subkeys; *ptr != subkey; ptr++)
		;

	nidx = ptr + 1 - key->subkeys;
	memmove(ptr, ptr+1, (key->nsubkeys - nidx) * sizeof(*ptr));

	key->subkeys[key->nsubkeys-1] = subkey;
}

static void set_subkey_name(struct check_ctx *ctx, struct regkey *key,
			    const char *name, int nlen)
{
	char *path = key->path;
	TALLOC_CTX *mem_ctx = talloc_new(talloc_tos());
	char *p;
	struct regkey *subkey;
	char *nname = talloc_strndup(mem_ctx, name, nlen);
	remove_all(nname, ctx->sep);

	if (strncmp(name, nname, nlen) != 0) {
		/* XXX interaction: delete/edit */
		printf("Warning: invalid name: \"%s\" replace with \"%s\"\n",
		       name, nname);
		key->needs_update = true;
	}
	p = talloc_asprintf_strupper_m(mem_ctx, "%s%c%s",
				       path, ctx->sep, nname);
	subkey = check_ctx_lookup_key(ctx, p);
	if (subkey->name) {
		bool do_replace = false;

		if (strcmp(subkey->name, nname) != 0) {
			int action;
			char default_action;

			if (is_all_upper(nname)) {
				default_action = 'o';
			} else {
				default_action = 'n';
			}

			printf("Conflicting subkey names of [%s]: "
			       "old: \"%s\", new: \"%s\"\n",
			       key->path, subkey->name, nname);

			if (ctx->opt.output == NULL || ctx->opt.automatic) {
				action = default_action;
			} else {
				do {
					action = interact_prompt(
						"choose spelling [o]ld, [n]ew,"
						"or [e]dit", "one",
						default_action);
					if (action == 'e') {
						printf("Sorry, edit is not yet "
						       "implemented here...\n");
					}
				} while (action == 'e');
			}

			if (action == 'n') {
				do_replace = true;
			}
		}

		if (do_replace) {
			if (ctx->opt.verbose) {
				printf("Replacing name: %s: \"%s\""
				       " -> \"%s\"\n", path,
				       subkey->name, nname);
			}
			TALLOC_FREE(subkey->name);
			subkey->name = talloc_steal(subkey, nname);
			key->needs_update = true;
		}
	} else {
		if (ctx->opt.verbose) {
			printf("Set name: %s: \"%s\"\n", path, nname);
		}
		subkey->name = talloc_steal(subkey, nname);
	}

	move_to_back(key, subkey);
	TALLOC_FREE(mem_ctx);
}

static void
read_subkeys(struct check_ctx *ctx, const char *path, TDB_DATA val, bool update)
{
	uint32_t num_items, found_items = 0;
	char *subkey;
	struct regkey *key = check_ctx_lookup_key(ctx, path);

	key->needs_update |= update;

	/* printf("SUBKEYS: %s\n", path); */
	if (key->has_subkeylist) {
		printf("Duplicate subkeylist \"%s\"\n",
		       path);
		found_items = key->nsubkeys;
	}

	/* exists as defined by regdb_key_exists() */
	key->has_subkeylist = true;

	/* name is set if a key is referenced by the */
	/* subkeylist of its parent. */

	if (!tdb_data_read_uint32(&val, &num_items) ) {
		printf("Invalid subkeylist: \"%s\"\n", path);
		return;
	}

	while (tdb_data_read_cstr(&val, &subkey)) {
		/* printf(" SUBKEY: %s\n", subkey); */
		set_subkey_name(ctx, key, subkey, strlen(subkey));
		found_items++;
	}

	if (val.dsize != 0) {
		printf("Subkeylist of \"%s\": trailing: \"%.*s\"\n",
		       path, (int)val.dsize, val.dptr);
		/* ask: best effort, delete or edit?*/
		set_subkey_name(ctx, key, (char*)val.dptr, val.dsize);
		found_items++;
		key->needs_update = true;
	}

	if (num_items != found_items) {
		printf("Subkeylist of \"%s\": invalid number of subkeys, "
		       "expected: %d got: %d\n", path, num_items, found_items);
		key->needs_update = true;
	}

}

static void read_values(struct check_ctx *ctx, const char *path, TDB_DATA val)
{
	struct regkey *key = check_ctx_lookup_key(ctx, path);
	uint32_t num_items, found_items;
	struct regval value;

	/* printf("VALUES: %s\n", path); */

	if (!tdb_data_read_uint32(&val, &num_items) ) {
		printf("Invalid valuelist: \"%s\"\n", path);
		return;
	}

	found_items=0;
	while (tdb_data_read_regval(&val, &value)) {
		/* printf(" VAL: %s type: %s(%d) length: %d\n", value.name, */
		/*        str_regtype(value.type), value.type, */
		/*        (int)value.data.length); */
		regkey_add_regval(key, regval_copy(key, &value));
		found_items++;
	}

	if (num_items != found_items) {
		printf("Valuelist of \"%s\": invalid number of values, "
		       "expected: %d got: %d\n", path, num_items, found_items);
		key->needs_update = true;
	}

	if (val.dsize != 0) {
		printf("Valuelist of \"%s\": trailing: \"%*s\"\n", path,
		       (int)val.dsize, val.dptr);
		key->needs_update = true;
		/* XXX best effort ??? */
		/* ZERO_STRUCT(value); */
		/* if (tdb_data_read_cstr(&val, &value.name) */
		/*     && tdb_data_read_uint32(&val, &value.type)) */
		/* { */
		/*	uint32_t len = -1; */
		/*	tdb_data_read_uint32(&val, &len); */
		/*	... */
		/*	found_items ++; */
		/*	regkey_add_regval(key, regval_copy(key, value)); */
		/* } */
	}
	if (found_items == 0) {
		printf("Valuelist of \"%s\" empty\n", path);
		key->needs_update = true;
	}
}

static bool read_sorted(struct check_ctx *ctx, const char *path, TDB_DATA val)
{
	if (ctx->version >= 3) {
		return false;
	}

	if ((val.dptr == NULL) || (val.dsize<4)) {
		return false;
	}

	/* ToDo: check */
	/* struct regkey *key = check_ctx_lookup_key(ctx, path); */
	/* printf("SORTED: %s\n", path); */
	return true;
}

static bool read_sd(struct check_ctx *ctx, const char *path, TDB_DATA val)
{
	NTSTATUS status;
	struct regkey *key = check_ctx_lookup_key(ctx, path);
	/* printf("SD: %s\n", path); */

	status = unmarshall_sec_desc(key, val.dptr, val.dsize, &key->sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to read SD of %s: %s\n",
			  path, nt_errstr(status)));
	}
	return true;
}

static bool srprs_path(const char **ptr, const char* prefix, char sep,
		       const char **ppath)
{
	const char *path, *pos = *ptr;
	if (prefix != NULL) {
		if (!srprs_str(&pos, prefix, -1) || !srprs_char(&pos, sep) ) {
			return false;
		}
	}
	path = pos;
	if ( !srprs_hive(&pos, NULL) ) {
		return false;
	}
	if ( !srprs_eos(&pos) && !srprs_char(&pos, sep) ) {
		return false;
	}
	*ppath = path;
	*ptr = strchr(pos, '\0');
	return true;
}

/* Fixme: this dosn't work in the general multibyte char case.
   see string_replace()
*/
static bool normalize_path_internal(char* path, char sep) {
	size_t len = strlen(path);
	const char *orig = talloc_strndup(talloc_tos(), path, len);
	char *optr = path, *iptr = path;
	bool changed;

	while (*iptr == sep ) {
		iptr++;
	}
	while (*iptr) {
		*optr = *iptr;
		if (*iptr == sep) {
			while (*iptr == sep) {
				iptr++;
			}
			if (*iptr) {
				optr++;
			}
		} else {
			iptr++;
			optr++;
		}
	}
	*optr = '\0';

	if (!strupper_m(path)) {
		talloc_free(discard_const(orig));
		return false;
	}
	changed = (strcmp(orig, path) != 0);
	talloc_free(discard_const(orig));
	return changed;
}

static bool normalize_path(char* path, char sep) {
	static const char* SEPS = "\\/";
	char* firstsep = strpbrk(path, SEPS);
	bool wrong_sep = (firstsep && (*firstsep != sep));

	assert (strchr(SEPS, sep));

	if (wrong_sep) {
		string_replace(path, *firstsep, sep);
	}
	return normalize_path_internal(path, sep) || wrong_sep;
}

static int check_tdb_action(struct db_record *rec, void *check_ctx)
{
	struct check_ctx *ctx = (struct check_ctx*)check_ctx;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA val = dbwrap_record_get_value(rec);
	TDB_DATA rec_key = dbwrap_record_get_key(rec);
	char *key;
	bool invalid_path = false;
	bool once_more;
	bool first_iter = true;

	if (!tdb_data_is_cstr(rec_key)) {
		printf("Key is not zero terminated: \"%.*s\"\ntry to go on.\n",
		       (int)rec_key.dsize, rec_key.dptr);
		invalid_path = true;
	}
	key = talloc_strndup(frame, (char*)rec_key.dptr, rec_key.dsize);

	do {
		const char *path, *pos = key;
		once_more = false;

		if (srprs_str(&pos, "INFO/", -1)) {
			if ( read_info(ctx, pos, val) ) {
				break;
			}
			invalid_path = true;
			/* ask: mark invalid */
		} else if (srprs_str(&pos, "__db_sequence_number__", -1)) {
			printf("Skip key: \"%.*s\"\n",
			       (int)rec_key.dsize, rec_key.dptr);
			/* skip: do nothing + break */
			break;

		} else if (normalize_path(key, ctx->sep)) {
			printf("Unnormal key: \"%.*s\"\n",
			       (int)rec_key.dsize, rec_key.dptr);
			printf("Normalize to: \"%s\"\n", key);
			invalid_path = true;
		} else if (srprs_path(&pos, NULL,
				      ctx->sep, &path))
		{
			read_subkeys(ctx, path, val, invalid_path);
			break;
		} else if (srprs_path(&pos, REG_VALUE_PREFIX,
				      ctx->sep, &path))
		{
			read_values(ctx, path, val);
			break;
		} else if (srprs_path(&pos, REG_SECDESC_PREFIX,
				      ctx->sep, &path))
		{
			read_sd(ctx, path, val);
			break;
		} else if (srprs_path(&pos, REG_SORTED_SUBKEYS_PREFIX,
				      ctx->sep, &path))
		{
			if (!read_sorted(ctx, path, val)) {
				/* delete: mark invalid + break */
				printf("Invalid sorted subkeys for: \"%s\"\n", path);
				invalid_path = true;
				key = NULL;
			}
			break;
		} else {
			printf("Unrecognized key: \"%.*s\"\n",
			       (int)rec_key.dsize, rec_key.dptr);
			invalid_path = true;
		}

		if (invalid_path) {
			unsigned char action;
			if (ctx->opt.output == NULL) {
				action = first_iter ? 'r' : 's';
			} else if (ctx->opt.automatic) {
				action = first_iter ? 'r' : 'd';
			} else if (ctx->auto_action != '\0') {
				action = ctx->auto_action;
			} else {
				action = interact_prompt("[s]kip,[S]kip all,"
							 "[d]elete,[D]elete all"
							 ",[e]dit,[r]etry"
							 , "sder",
							 ctx->default_action);
			}
			if (isupper(action)) {
				action = tolower(action);
				ctx->auto_action = action;
			}
			ctx->default_action = action;
			switch (action) {
			case 's': /* skip */
				invalid_path = false;
				break;
			case 'd': /* delete */
				invalid_path = true;
				key = NULL;
				break;
			case 'e': /* edit */ {
				char *p = interact_edit(frame, key);
				if (p) {
					talloc_free(key);
					key = p;
				}
			} /* fall through */
			case 'r': /* retry */
				once_more = true;
				break;
			}
		}
		first_iter = false;
	} while (once_more);

	if (invalid_path) {
		dbwrap_store(ctx->del, rec_key, string_term_tdb_data(key), 0);
	}

	talloc_free(frame);
	return 0;
}

static bool get_version(struct check_ctx *ctx) {
	static const uint32_t curr_version = REGDB_CODE_VERSION;
	uint32_t version = ctx->opt.version ? ctx->opt.version : curr_version;
	uint32_t info_version = 0;
	NTSTATUS status;

	status = dbwrap_fetch_uint32_bystring(ctx->idb, "INFO/version",
					      &info_version);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Warning: no INFO/version found!\n");
		/* info_version = guess_version(ctx); */
	}

	if (ctx->opt.version) {
		version = ctx->opt.version;
	} else if (ctx->opt.implicit_db) {
		version = curr_version;
	} else {
		version = info_version;
	}

	if (!version) {
		printf("Couldn't determine registry format version, "
		       "specify with --reg-version\n");
		return false;
	}


	if ( version != info_version ) {
		if (ctx->opt.force || !ctx->opt.repair) {
			printf("Warning: overwrite registry format "
			       "version %d with %d\n", info_version, version);
		} else {
			printf("Warning: found registry format version %d but "
			       "expected %d, use --force to proceed.\n", info_version, version);
			return false;
		}
	}

	ctx->version = version;
	ctx->sep = (version > 1) ? '\\' : '/';

	return true;
}

static bool
dbwrap_store_verbose(struct db_context *db, const char *key, TDB_DATA nval)
{
	TALLOC_CTX *mem_ctx = talloc_new(talloc_tos());
	TDB_DATA oval;
	NTSTATUS status;

	status = dbwrap_fetch_bystring(db, mem_ctx, key, &oval);
	if (NT_STATUS_IS_OK(status)) {
		if (tdb_data_equal(nval, oval)) {
			goto done;
		}
		printf("store %s:\n  overwrite: %s\n  with:      %s\n", key,
		       tdb_data_print(mem_ctx, oval),
		       tdb_data_print(mem_ctx, nval));

	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		printf("store %s:\n  write: %s\n", key,
		       tdb_data_print(mem_ctx, nval));
	} else {
		printf ("store %s:\n  failed to fetch old value: %s\n", key,
			nt_errstr(status));
		goto done;
	}

	status = dbwrap_store_bystring(db, key, nval, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf ("store %s failed: %s\n", key, nt_errstr(status));
	}

done:
	talloc_free(mem_ctx);
	return NT_STATUS_IS_OK(status);
}

static bool
dbwrap_store_uint32_verbose(struct db_context *db, const char *key, uint32_t nval)
{
	uint32_t oval;
	NTSTATUS status;

	status = dbwrap_fetch_uint32_bystring(db, key, &oval);
	if (NT_STATUS_IS_OK(status)) {
		if (nval == oval) {
			goto done;
		}
		printf("store %s:\n overwrite: %d\n with:      %d\n", key,
		       (int)oval, (int)nval);

	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		printf("store %s:\n write: %d\n", key, (int)nval);
	} else {
		printf ("store %s:\n  failed to fetch old value: %s\n", key,
			nt_errstr(status));
		goto done;
	}

	status = dbwrap_store_uint32_bystring(db, key, nval);
	if (!NT_STATUS_IS_OK(status)) {
		printf ("store %s failed: %s\n", key, nt_errstr(status));
	}

done:
	return NT_STATUS_IS_OK(status);
}

static int cmp_keynames(char **p1, char **p2)
{
	return strcasecmp_m(*p1, *p2);
}

static bool
write_subkeylist(struct db_context *db, struct regkey *key, char sep)
{
	cbuf *buf = cbuf_new(talloc_tos());
	int i;
	bool ret;

	cbuf_putdw(buf, key->nsubkeys);

	for (i=0; i < key->nsubkeys; i++) {
		struct regkey *subkey = key->subkeys[i];
		const char *name = subkey->name;
		if (name == NULL) {
			printf("Warning: no explicite name for key %s\n",
			       subkey->path);
			name = strrchr_m(subkey->path, sep);
			assert(name);
			name ++;
		}
		cbuf_puts(buf, name, -1);
		cbuf_putc(buf, '\0');
	}

	ret = dbwrap_store_verbose(db, key->path, cbuf_make_tdb_data(buf));

	talloc_free(buf);
	return ret;
}

static bool write_sorted(struct db_context *db, struct regkey *key, char sep)
{
	cbuf *buf = cbuf_new(talloc_tos());
	char *path;
	int i;
	bool ret = false;
	char **sorted = talloc_zero_array(buf, char*, key->nsubkeys);
	int offset =  (1 + key->nsubkeys) * sizeof(uint32_t);

	for (i=0; i < key->nsubkeys; i++) {
		sorted[i] = talloc_strdup_upper(sorted, key->subkeys[i]->name);
	}
	TYPESAFE_QSORT(sorted, key->nsubkeys, cmp_keynames);

	cbuf_putdw(buf, key->nsubkeys);
	for (i=0; i < key->nsubkeys; i++) {
		cbuf_putdw(buf, offset);
		offset += strlen(sorted[i]) + 1;
	}
	for (i=0; i < key->nsubkeys; i++) {
		cbuf_puts(buf, sorted[i], -1);
		cbuf_putc(buf, '\0');
	}

	path = talloc_asprintf(buf, "%s%c%s", REG_SORTED_SUBKEYS_PREFIX, sep,
			       key->path);
	if (path == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	ret = dbwrap_store_verbose(db, path, cbuf_make_tdb_data(buf));
done:
	talloc_free(buf);
	return ret;
}

static bool write_values(struct db_context *db, struct regkey *key, char sep)
{
	cbuf *buf = cbuf_new(talloc_tos());
	char *path;
	int i;
	bool ret = false;

	cbuf_putdw(buf, key->nvalues);
	for (i=0; i < key->nvalues; i++) {
		struct regval *val = key->values[i];
		cbuf_puts(buf, val->name, -1);
		cbuf_putc(buf, '\0');
		cbuf_putdw(buf, val->type);
		cbuf_putdw(buf, val->data.length);
		cbuf_puts(buf, (void*)val->data.data, val->data.length);
	}

	path = talloc_asprintf(buf, "%s%c%s", REG_VALUE_PREFIX, sep, key->path);
	if (path == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	ret = dbwrap_store_verbose(db, path, cbuf_make_tdb_data(buf));
done:
	talloc_free(buf);
	return ret;
}

static bool write_sd(struct db_context *db, struct regkey *key, char sep)
{
	TDB_DATA sd;
	NTSTATUS status;
	char *path;
	bool ret = false;
	TALLOC_CTX *mem_ctx = talloc_new(talloc_tos());

	status = marshall_sec_desc(mem_ctx, key->sd, &sd.dptr, &sd.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		printf("marshall sec desc %s failed: %s\n",
		       key->path, nt_errstr(status));
		goto done;
	}
	path = talloc_asprintf(mem_ctx, "%s%c%s", REG_SECDESC_PREFIX,
			       sep, key->path);
	if (path == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	ret = dbwrap_store_verbose(db, path, sd);
done:
	talloc_free(mem_ctx);
	return ret;
}


static int check_write_db_action(struct db_record *rec, void *check_ctx)
{
	struct check_ctx *ctx = (struct check_ctx*)check_ctx;
	TDB_DATA rec_val = dbwrap_record_get_value(rec);
	struct regkey *key = *(struct regkey**)rec_val.dptr;
	TALLOC_CTX *frame = talloc_stackframe();

	/* write subkeylist */
	if ((ctx->version > 2) || (key->nsubkeys > 0) || (key->has_subkeylist)) {
		write_subkeylist(ctx->odb, key, ctx->sep);
	}

	/* write sorted subkeys */
	if ((ctx->version < 3) && (key->nsubkeys > 0)) {
		write_sorted(ctx->odb, key, ctx->sep);
	}

	/* write value list */
	if (key->nvalues > 0) {
		write_values(ctx->odb, key, ctx->sep);
	}

	/* write sd */
	if (key->sd) {
		write_sd(ctx->odb, key, ctx->sep);
	}

	talloc_free(frame);
	return 0;
}

static int fix_tree_action(struct db_record *rec, void *check_ctx)
{
	struct check_ctx *ctx = (struct check_ctx*)check_ctx;
	TDB_DATA rec_key = dbwrap_record_get_key(rec);
	TDB_DATA rec_val = dbwrap_record_get_value(rec);
	struct regkey* key = *(struct regkey**)rec_val.dptr;
	if (ctx->opt.verbose) {
		printf("Check Tree: %s\n", key->path);
	}

	assert (strncmp(key->path, (char*)rec_key.dptr, rec_key.dsize) == 0);

	/* assert(dbwrap_exists(ctx->db, string_term_tdb_data(key->path)) */
	/*        == key->exists); */

	if (key->needs_update) {
		printf("Update key: \"%s\"\n", key->path);
		if ((ctx->version > 2) || (key->nsubkeys > 0)) {
			write_subkeylist(ctx->odb, key, ctx->sep);
		}
		if ((ctx->version <= 2) && (key->nsubkeys > 0)) {
			write_sorted(ctx->odb, key, ctx->sep);
		}
		if (key->nvalues > 0) {
			write_values(ctx->odb, key, ctx->sep);
		}
		if (key->sd) {
			write_sd(ctx->odb, key, ctx->sep);
		}
	} else if (!key->has_subkeylist) {
		if ((ctx->version > 2) || (key->nsubkeys > 0)) {
			printf("Missing subkeylist: %s\n", key->path);
			write_subkeylist(ctx->odb, key, ctx->sep);
		}
	}

	if (key->name == NULL && key->parent->has_subkeylist) {
		printf("Key not referenced by the its parents subkeylist: %s\n",
		       key->path);
		write_subkeylist(ctx->odb, key->parent, ctx->sep);
	}

/* XXX check that upcase(name) matches last part of path ??? */

	return 0;
}


/* give the same warnings as fix_tree_action */
static int check_tree_action(struct db_record *rec, void *check_ctx)
{
	struct check_ctx *ctx = (struct check_ctx*)check_ctx;
	TDB_DATA rec_key = dbwrap_record_get_key(rec);
	TDB_DATA rec_val = dbwrap_record_get_value(rec);
	struct regkey* key = *(struct regkey**)rec_val.dptr;
	if (ctx->opt.verbose) {
		printf("Check Tree: %s\n", key->path);
	}

	assert (strncmp(key->path, (char*)rec_key.dptr, rec_key.dsize) == 0);

	if (!key->has_subkeylist) {
		if ((ctx->version > 2) || (key->nsubkeys > 0)) {
			printf("Missing subkeylist: %s\n", key->path);
		}
	}

	if (key->name == NULL && key->parent->has_subkeylist) {
		printf("Key not referenced by the its parents subkeylist: %s\n",
		       key->path);
	}

	return 0;
}

static int delete_invalid_action(struct db_record *rec, void* check_ctx)
{
	NTSTATUS status;
	struct check_ctx *ctx = (struct check_ctx*)check_ctx;
	TDB_DATA rec_key = dbwrap_record_get_key(rec);
	TDB_DATA rec_val = dbwrap_record_get_value(rec);


	printf("Delete key: \"%.*s\"",(int)rec_key.dsize, rec_key.dptr);
	if (rec_val.dsize > 0) {
		printf(" in favour of \"%s\"\n", rec_val.dptr);
	} else {
		putc('\n', stdout);
	}

	status = dbwrap_delete(ctx->odb, rec_key);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("delete key \"%.*s\" failed!\n",
			 (int)rec_key.dsize, rec_key.dptr);
		return -1;
	}
	return 0;
}

static bool check_ctx_check_tree(struct check_ctx *ctx) {
	NTSTATUS status;

	status = dbwrap_traverse(ctx->reg, check_tree_action, ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("check traverse failed: %s\n",
			  nt_errstr(status)));
		return false;
	}
	return true;
}
static bool check_ctx_fix_inplace(struct check_ctx *ctx) {
	NTSTATUS status;
	status = dbwrap_traverse(ctx->reg, fix_tree_action, ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fix traverse failed: %s\n", nt_errstr(status)));
		return false;
	}

	status = dbwrap_traverse(ctx->del, delete_invalid_action, ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("delete traverse failed: %s\n", nt_errstr(status)));
		return false;
	}

	if (!dbwrap_store_uint32_verbose(ctx->odb, "INFO/version", ctx->version)) {
		DEBUG(0, ("storing version failed: %s\n", nt_errstr(status)));
		return false;
	}

	return true;
}

static bool check_ctx_write_new_db(struct check_ctx *ctx) {
	NTSTATUS status;

	assert(ctx->odb);

	if (ctx->opt.wipe) {
		int ret = dbwrap_wipe(ctx->odb);
		if (ret != 0) {
			DEBUG(0, ("wiping %s failed\n", ctx->opt.output));
			return false;
		}
	}

	status = dbwrap_traverse(ctx->reg, check_write_db_action, ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("traverse2 failed: %s\n", nt_errstr(status)));
		return false;
	}

	status = dbwrap_store_uint32_bystring(ctx->odb, "INFO/version",
					      ctx->version);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("write version failed: %s\n", nt_errstr(status)));
		return false;
	}
	return true;
}

int net_registry_check_db(const char *name, const struct check_options *opt)
{
	NTSTATUS status;
	int ret = -1;
	struct check_ctx *ctx = check_ctx_create(talloc_tos(), name, opt);
	if (ctx==NULL) {
		goto done;
	}

	d_printf("Check database: %s\n", name);

	/* 1. open output RW */
	if (!check_ctx_open_output(ctx)) {
		goto done;
	}

	/* 2. open input RO */
	if (!check_ctx_open_input(ctx)) {
		goto done;
	}

	if (opt->lock && !check_ctx_transaction_start(ctx)) {
		goto done;
	}

	if (!get_version(ctx)) {
		goto done;
	}

	status = dbwrap_traverse_read(ctx->idb, check_tdb_action, ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("check traverse failed: %s\n", nt_errstr(status)));
		goto done;
	}

	if (!opt->lock && !check_ctx_transaction_start(ctx)) {
		goto done;
	}

	if (ctx->opt.repair && !ctx->opt.wipe) {
		if (!check_ctx_fix_inplace(ctx)) {
			goto done;
		}
	} else {
		if (!check_ctx_check_tree(ctx)) {
			goto done;
		}
		if (ctx->odb) {
			if (!check_ctx_write_new_db(ctx)) {
				goto done;
			}
		}
	}
	ret = 0;
done:
	check_ctx_transaction_stop(ctx, ret == 0);

	talloc_free(ctx);
	return ret;
}

/*Local Variables:*/
/*mode: c*/
/*End:*/
