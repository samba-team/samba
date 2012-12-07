/*
   Samba Unix/Linux SMB client library
   Distributed SMB/CIFS Server Management Utility
   Copyright (C) 2003 Andrew Bartlett (abartlet@samba.org)

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

#include "includes.h"
#include "system/filesys.h"
#include "utils/net.h"
#include "secrets.h"
#include "idmap.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "net_idmap_check.h"
#include "util_tdb.h"

#define ALLOC_CHECK(mem) do { \
	if (!mem) { \
		d_fprintf(stderr, _("Out of memory!\n")); \
		talloc_free(ctx); \
		return -1; \
	} } while(0)

enum idmap_dump_backend {
	TDB,
	AUTORID
};

struct idmap_dump_ctx {
	enum idmap_dump_backend backend;
};

static int net_idmap_dump_one_autorid_entry(struct db_record *rec,
					    void *unused)
{
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	if (strncmp((char *)key.dptr, "CONFIG", 6) == 0) {
		char *config = talloc_array(talloc_tos(), char, value.dsize+1);
		memcpy(config, value.dptr, value.dsize);
		config[value.dsize] = '\0';
		printf("CONFIG: %s\n", config);
		talloc_free(config);
		return 0;
	}

	if (strncmp((char *)key.dptr, "NEXT RANGE", 10) == 0) {
		printf("RANGE HWM: %"PRIu32"\n", IVAL(value.dptr, 0));
		return 0;
	}

	if (strncmp((char *)key.dptr, "NEXT ALLOC UID", 14) == 0) {
		printf("UID HWM: %"PRIu32"\n", IVAL(value.dptr, 0));
		return 0;
	}

	if (strncmp((char *)key.dptr, "NEXT ALLOC GID", 14) == 0) {
		printf("GID HWM: %"PRIu32"\n", IVAL(value.dptr, 0));
		return 0;
	}

	if (strncmp((char *)key.dptr, "UID", 3) == 0 ||
	    strncmp((char *)key.dptr, "GID", 3) == 0)
	{
		/* mapped entry from allocation pool */
		printf("%s %s\n", value.dptr, key.dptr);
		return 0;
	}

	if ((strncmp((char *)key.dptr, "S-1-5-", 6) == 0 ||
	     strncmp((char *)key.dptr, "ALLOC", 5) == 0) &&
	    value.dsize == sizeof(uint32_t))
	{
		/* this is a domain range assignment */
		uint32_t range = IVAL(value.dptr, 0);
		printf("RANGE %"PRIu32": %s\n", range, key.dptr);
		return 0;
	}

	return 0;
}

/***********************************************************
 Helper function for net_idmap_dump. Dump one entry.
 **********************************************************/
static int net_idmap_dump_one_tdb_entry(struct db_record *rec,
					void *unused)
{
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	if (strcmp((char *)key.dptr, "USER HWM") == 0) {
		printf(_("USER HWM %d\n"), IVAL(value.dptr,0));
		return 0;
	}

	if (strcmp((char *)key.dptr, "GROUP HWM") == 0) {
		printf(_("GROUP HWM %d\n"), IVAL(value.dptr,0));
		return 0;
	}

	if (strncmp((char *)key.dptr, "S-", 2) != 0) {
		return 0;
	}

	printf("%s %s\n", value.dptr, key.dptr);
	return 0;
}

static const char* net_idmap_dbfile(struct net_context *c,
				    struct idmap_dump_ctx *ctx)
{
	const char* dbfile = NULL;
	const char *backend = NULL;

	backend = lp_idmap_default_backend();
	if (!backend) {
		d_printf(_("Internal error: 'idmap config * : backend' is not set!\n"));
		return NULL;
	}

	if (c->opt_db != NULL) {
		dbfile = talloc_strdup(talloc_tos(), c->opt_db);
		if (dbfile == NULL) {
			d_fprintf(stderr, _("Out of memory!\n"));
		}
	} else if (strequal(backend, "tdb")) {
		dbfile = state_path("winbindd_idmap.tdb");
		if (dbfile == NULL) {
			d_fprintf(stderr, _("Out of memory!\n"));
		}
		ctx->backend = TDB;
	} else if (strequal(backend, "tdb2")) {
		dbfile = talloc_asprintf(talloc_tos(), "%s/idmap2.tdb",
					 lp_private_dir());
		if (dbfile == NULL) {
			d_fprintf(stderr, _("Out of memory!\n"));
		}
		ctx->backend = TDB;
	} else if (strequal(backend, "autorid")) {
		dbfile = state_path("autorid.tdb");
		if (dbfile == NULL) {
			d_fprintf(stderr, _("Out of memory!\n"));
		}
		ctx->backend = AUTORID;
	} else {
		char *_backend = talloc_strdup(talloc_tos(), backend);
		char* args = strchr(_backend, ':');
		if (args != NULL) {
			*args = '\0';
		}

		d_printf(_("Sorry, 'idmap backend = %s' is currently not supported\n"),
			   _backend);

		talloc_free(_backend);
	}

	return dbfile;
}

/***********************************************************
 Dump the current idmap
 **********************************************************/
static int net_idmap_dump(struct net_context *c, int argc, const char **argv)
{
	struct db_context *db;
	TALLOC_CTX *mem_ctx;
	const char* dbfile;
	NTSTATUS status;
	int ret = -1;
	struct idmap_dump_ctx ctx = { .backend = TDB };

	if ( argc > 1  || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap dump [[--db=]<inputfile>]\n"
			   "  Dump current ID mapping.\n"
			   "    inputfile\tTDB file to read mappings from.\n"));
		return c->display_usage?0:-1;
	}

	mem_ctx = talloc_stackframe();

	dbfile = (argc > 0) ? argv[0] : net_idmap_dbfile(c, &ctx);
	if (dbfile == NULL) {
		goto done;
	}
	d_fprintf(stderr, _("dumping id mapping from %s\n"), dbfile);

	db = db_open(mem_ctx, dbfile, 0, TDB_DEFAULT, O_RDONLY, 0,
		     DBWRAP_LOCK_ORDER_1);
	if (db == NULL) {
		d_fprintf(stderr, _("Could not open idmap db (%s): %s\n"),
			  dbfile, strerror(errno));
		goto done;
	}

	if (ctx.backend == AUTORID) {
		status = dbwrap_traverse_read(db,
					      net_idmap_dump_one_autorid_entry,
					      NULL, NULL);
	} else {
		status = dbwrap_traverse_read(db,
					      net_idmap_dump_one_tdb_entry,
					      NULL, NULL);
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("error traversing the database\n"));
		ret = -1;
		goto done;
	}

	ret = 0;

done:
	talloc_free(mem_ctx);
	return ret;
}

/***********************************************************
 Write entries from stdin to current local idmap
 **********************************************************/

static int net_idmap_store_id_mapping(struct db_context *db,
				      enum id_type type,
				      unsigned long idval,
				      const char *sid_string)
{
	NTSTATUS status;
	char *idstr = NULL;

	switch(type) {
	case ID_TYPE_UID:
		idstr = talloc_asprintf(talloc_tos(), "UID %lu", idval);
		break;
	case ID_TYPE_GID:
		idstr = talloc_asprintf(talloc_tos(), "GID %lu", idval);
		break;
	default:
		d_fprintf(stderr, "Invalid id mapping type: %d\n", type);
		return -1;
	}

	status = dbwrap_store_bystring(db, idstr,
				       string_term_tdb_data(sid_string),
				       TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Error storing ID -> SID: "
			 "%s\n", nt_errstr(status));
		talloc_free(idstr);
		return -1;
	}
	status = dbwrap_store_bystring(db, sid_string,
				       string_term_tdb_data(idstr),
				       TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Error storing SID -> ID: "
			 "%s\n", nt_errstr(status));
		talloc_free(idstr);
		return -1;
	}

	return 0;
}

static int net_idmap_restore(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	FILE *input = NULL;
	struct db_context *db;
	const char *dbfile = NULL;
	int ret = 0;
	struct idmap_dump_ctx ctx = { .backend = TDB };

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap restore [--db=<TDB>] [<inputfile>]\n"
			   "  Restore ID mappings from file\n"
			   "    TDB\tFile to store ID mappings to."
			   "    inputfile\tFile to load ID mappings from. If not "
			   "given, load data from stdin.\n"));
		return 0;
	}

	mem_ctx = talloc_stackframe();

	dbfile = net_idmap_dbfile(c, &ctx);

	if (dbfile == NULL) {
		ret = -1;
		goto done;
	}

	if (ctx.backend != TDB) {
		d_fprintf(stderr, _("Sorry, restoring of non-TDB databases is "
				    "currently not supported\n"));
		ret = -1;
		goto done;
	}

	d_fprintf(stderr, _("restoring id mapping to %s\n"), dbfile);

	if (argc == 1) {
		input = fopen(argv[0], "r");
		if (input == NULL) {
			d_fprintf(stderr, _("Could not open input file (%s): %s\n"),
				  argv[0], strerror(errno));
			ret = -1;
			goto done;
		}
	} else {
		input = stdin;
	}

	db = db_open(mem_ctx, dbfile, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0644,
		     DBWRAP_LOCK_ORDER_1);
	if (db == NULL) {
		d_fprintf(stderr, _("Could not open idmap db (%s): %s\n"),
			  dbfile, strerror(errno));
		ret = -1;
		goto done;
	}

	if (dbwrap_transaction_start(db) != 0) {
		d_fprintf(stderr, _("Failed to start transaction.\n"));
		ret = -1;
		goto done;
	}

	while (!feof(input)) {
		char line[128], sid_string[128];
		int len;
		unsigned long idval;
		NTSTATUS status;

		if (fgets(line, 127, input) == NULL)
			break;

		len = strlen(line);

		if ( (len > 0) && (line[len-1] == '\n') )
			line[len-1] = '\0';

		if (sscanf(line, "GID %lu %128s", &idval, sid_string) == 2)
		{
			ret = net_idmap_store_id_mapping(db, ID_TYPE_GID,
							 idval, sid_string);
			if (ret != 0) {
				break;
			}
		} else if (sscanf(line, "UID %lu %128s", &idval, sid_string) == 2)
		{
			ret = net_idmap_store_id_mapping(db, ID_TYPE_UID,
							 idval, sid_string);
			if (ret != 0) {
				break;
			}
		} else if (sscanf(line, "USER HWM %lu", &idval) == 1) {
			status = dbwrap_store_int32_bystring(
				db, "USER HWM", idval);
			if (!NT_STATUS_IS_OK(status)) {
				d_fprintf(stderr,
					  _("Could not store USER HWM: %s\n"),
					  nt_errstr(status));
				break;
			}
		} else if (sscanf(line, "GROUP HWM %lu", &idval) == 1) {
			status = dbwrap_store_int32_bystring(
				db, "GROUP HWM", idval);
			if (!NT_STATUS_IS_OK(status)) {
				d_fprintf(stderr,
					  _("Could not store GROUP HWM: %s\n"),
					  nt_errstr(status));
				break;
			}
		} else {
			d_fprintf(stderr, _("ignoring invalid line [%s]\n"),
				  line);
			continue;
		}
	}

	if (ret == 0) {
		if(dbwrap_transaction_commit(db) != 0) {
			d_fprintf(stderr, _("Failed to commit transaction.\n"));
			ret = -1;
		}
	} else {
		if (dbwrap_transaction_cancel(db) != 0) {
			d_fprintf(stderr, _("Failed to cancel transaction.\n"));
		}
	}

done:
	if ((input != NULL) && (input != stdin)) {
		fclose(input);
	}

	talloc_free(mem_ctx);
	return ret;
}

static
NTSTATUS dbwrap_delete_mapping(struct db_context *db, TDB_DATA key1, bool force)
{
	TALLOC_CTX* mem_ctx = talloc_tos();
	bool is_valid_mapping;
	NTSTATUS status = NT_STATUS_OK;
	TDB_DATA val1, val2;

	ZERO_STRUCT(val1);
	ZERO_STRUCT(val2);

	status = dbwrap_fetch(db, mem_ctx, key1, &val1);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to fetch: %.*s\n", (int)key1.dsize, key1.dptr));
		goto done;
	}

	if (val1.dptr == NULL) {
		DEBUG(1, ("invalid mapping: %.*s -> empty value\n",
			  (int)key1.dsize, key1.dptr));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}

	DEBUG(2, ("mapping: %.*s -> %.*s\n",
		  (int)key1.dsize, key1.dptr, (int)val1.dsize, val1.dptr));

	status = dbwrap_fetch(db, mem_ctx, val1, &val2);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to fetch: %.*s\n", (int)val1.dsize, val1.dptr));
		goto done;
	}

	is_valid_mapping = tdb_data_equal(key1, val2);

	if (!is_valid_mapping) {
		DEBUG(1, ("invalid mapping: %.*s -> %.*s -> %.*s\n",
			  (int)key1.dsize, key1.dptr,
			  (int)val1.dsize, val1.dptr,
			  (int)val2.dsize, val2.dptr));
		if ( !force ) {
			status = NT_STATUS_FILE_INVALID;
			goto done;
		}
	}

	status = dbwrap_delete(db, key1);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to delete: %.*s\n", (int)key1.dsize, key1.dptr));
		goto done;
	}

	if (is_valid_mapping) {
		status = dbwrap_delete(db, val1);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("failed to delete: %.*s\n", (int)val1.dsize, val1.dptr));
		}
	}

done:
	TALLOC_FREE(val1.dptr);
	TALLOC_FREE(val2.dptr);
	return status;
}

static
NTSTATUS delete_mapping_action(struct db_context *db, void* data)
{
	return dbwrap_delete_mapping(db, *(TDB_DATA*)data, false);
}
static
NTSTATUS delete_mapping_action_force(struct db_context *db, void* data)
{
	return dbwrap_delete_mapping(db, *(TDB_DATA*)data, true);
}

/***********************************************************
 Delete a SID mapping from a winbindd_idmap.tdb
 **********************************************************/
static bool delete_args_ok(int argc, const char **argv)
{
	if (argc != 1)
		return false;
	if (strncmp(argv[0], "S-", 2) == 0)
		return true;
	if (strncmp(argv[0], "GID ", 4) == 0)
		return true;
	if (strncmp(argv[0], "UID ", 4) == 0)
		return true;
	return false;
}

static int net_idmap_delete(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;
	struct db_context *db;
	TALLOC_CTX *mem_ctx;
	TDB_DATA key;
	NTSTATUS status;
	const char* dbfile;
	struct idmap_dump_ctx ctx = { .backend = TDB };

	if ( !delete_args_ok(argc,argv) || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap delete [-f] [--db=<TDB>] <ID>\n"
			   "  Delete mapping of ID from TDB.\n"
			   "    -f\tforce\n"
			   "    TDB\tidmap database\n"
			   "    ID\tSID|GID|UID\n"));
		return c->display_usage ? 0 : -1;
	}

	mem_ctx = talloc_stackframe();

	dbfile = net_idmap_dbfile(c, &ctx);
	if (dbfile == NULL) {
		goto done;
	}
	d_fprintf(stderr, _("deleting id mapping from %s\n"), dbfile);

	db = db_open(mem_ctx, dbfile, 0, TDB_DEFAULT, O_RDWR, 0,
		     DBWRAP_LOCK_ORDER_1);
	if (db == NULL) {
		d_fprintf(stderr, _("Could not open idmap db (%s): %s\n"),
			  dbfile, strerror(errno));
		goto done;
	}

	key = string_term_tdb_data(argv[0]);

	status = dbwrap_trans_do(db, (c->opt_force
				      ? delete_mapping_action_force
				      : delete_mapping_action),  &key);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("could not delete mapping: %s\n"),
			  nt_errstr(status));
		goto done;
	}
	ret = 0;
done:
	talloc_free(mem_ctx);
	return ret;
}

static int net_idmap_set(struct net_context *c, int argc, const char **argv)
{
	d_printf("%s\n", _("Not implemented yet"));
	return -1;
}
static bool idmap_store_secret(const char *backend,
			       const char *domain,
			       const char *identity,
			       const char *secret)
{
	char *tmp;
	int r;
	bool ret;

	r = asprintf(&tmp, "IDMAP_%s_%s", backend, domain);

	if (r < 0) return false;

	/* make sure the key is case insensitive */
	if (!strupper_m(tmp)) {
		free(tmp);
		return false;
	}
	ret = secrets_store_generic(tmp, identity, secret);

	free(tmp);
	return ret;
}


static int net_idmap_secret(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	const char *secret;
	const char *dn;
	char *domain;
	char *backend;
	char *opt = NULL;
	bool ret;

	if (argc != 2 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:\n"),
			 _("net idmap secret <DOMAIN> <secret>\n"
			   "  Set the secret for the specified domain\n"
			   "    DOMAIN\tDomain to set secret for.\n"
			   "    secret\tNew secret to set.\n"));
		return c->display_usage?0:-1;
	}

	secret = argv[1];

	ctx = talloc_new(NULL);
	ALLOC_CHECK(ctx);

	domain = talloc_strdup(ctx, argv[0]);
	ALLOC_CHECK(domain);

	opt = talloc_asprintf(ctx, "idmap config %s", domain);
	ALLOC_CHECK(opt);

	backend = talloc_strdup(ctx, lp_parm_const_string(-1, opt, "backend", "tdb"));
	ALLOC_CHECK(backend);

	if ( ( ! backend) || ( ! strequal(backend, "ldap"))) {
		d_fprintf(stderr,
			  _("The only currently supported backend is LDAP\n"));
		talloc_free(ctx);
		return -1;
	}

	dn = lp_parm_const_string(-1, opt, "ldap_user_dn", NULL);
	if ( ! dn) {
		d_fprintf(stderr,
			  _("Missing ldap_user_dn option for domain %s\n"),
			  domain);
		talloc_free(ctx);
		return -1;
	}

	ret = idmap_store_secret("ldap", domain, dn, secret);

	if ( ! ret) {
		d_fprintf(stderr, _("Failed to store secret\n"));
		talloc_free(ctx);
		return -1;
	}

	d_printf(_("Secret stored\n"));
	return 0;
}

static int net_idmap_check(struct net_context *c, int argc, const char **argv)
{
	const char* dbfile;
	struct check_options opts;
	struct idmap_dump_ctx ctx = { .backend = TDB };

	if ( argc > 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap check  [-v] [-r] [-a] [-T] [-f] [-l] [[--db=]<TDB>]\n"
			   "  Check an idmap database.\n"
			   "    --verbose,-v\tverbose\n"
			   "    --repair,-r\trepair\n"
			   "    --auto,-a\tnoninteractive mode\n"
			   "    --test,-T\tdry run\n"
			   "    --fore,-f\tforce\n"
			   "    --lock,-l\tlock db while doing the check\n"
			   "    TDB\tidmap database\n"));
		return c->display_usage ? 0 : -1;
	}

	dbfile = (argc > 0) ? argv[0] : net_idmap_dbfile(c, &ctx);
	if (dbfile == NULL) {
		return -1;
	}

	if (ctx.backend != TDB) {
		d_fprintf(stderr, _("Sorry, checking of non-TDB databases is "
				    "currently not supported\n"));
		return -1;
	}

	d_fprintf(stderr, _("check database: %s\n"), dbfile);

	opts = (struct check_options) {
		.lock = c->opt_lock || c->opt_long_list_entries,
		.test = c->opt_testmode,
		.automatic = c->opt_auto,
		.verbose = c->opt_verbose,
		.force = c->opt_force,
		.repair = c->opt_repair || c->opt_reboot,
	};

	return net_idmap_check_db(dbfile, &opts);
}

/***********************************************************
 Look at the current idmap
 **********************************************************/
int net_idmap(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"dump",
			net_idmap_dump,
			NET_TRANSPORT_LOCAL,
			N_("Dump the current ID mappings"),
			N_("net idmap dump\n"
			   "  Dump the current ID mappings")
		},
		{
			"restore",
			net_idmap_restore,
			NET_TRANSPORT_LOCAL,
			N_("Restore entries from stdin"),
			N_("net idmap restore\n"
			   "  Restore entries from stdin")
		},
		{
			"setmap",
			net_idmap_set,
			NET_TRANSPORT_LOCAL,
			N_("Not implemented yet"),
			N_("net idmap setmap\n"
			   "  Not implemented yet")
		},
		{
			"delete",
			net_idmap_delete,
			NET_TRANSPORT_LOCAL,
			N_("Delete ID mapping"),
			N_("net idmap delete <ID>\n"
			   "  Delete ID mapping")
		},
		{
			"secret",
			net_idmap_secret,
			NET_TRANSPORT_LOCAL,
			N_("Set secret for specified domain"),
			N_("net idmap secret <DOMAIN> <secret>\n"
			   "  Set secret for specified domain")
		},
		{
			"check",
			net_idmap_check,
			NET_TRANSPORT_LOCAL,
			N_("Check id mappings"),
			N_("net idmap check\n"
			   "  Check id mappings")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net idmap", func);
}


