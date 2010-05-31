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

#define FOO(x) (x)
#include "includes.h"
#include "utils/net.h"
#include "secrets.h"

#define ALLOC_CHECK(mem) do { \
	if (!mem) { \
		d_fprintf(stderr, _("Out of memory!\n")); \
		talloc_free(ctx); \
		return -1; \
	} } while(0)

/***********************************************************
 Helper function for net_idmap_dump. Dump one entry.
 **********************************************************/
static int net_idmap_dump_one_entry(struct db_record *rec,
				    void *unused)
{
	if (strcmp((char *)rec->key.dptr, "USER HWM") == 0) {
		printf(_("USER HWM %d\n"), IVAL(rec->value.dptr,0));
		return 0;
	}

	if (strcmp((char *)rec->key.dptr, "GROUP HWM") == 0) {
		printf(_("GROUP HWM %d\n"), IVAL(rec->value.dptr,0));
		return 0;
	}

	if (strncmp((char *)rec->key.dptr, "S-", 2) != 0)
		return 0;

	printf("%s %s\n", rec->value.dptr, rec->key.dptr);
	return 0;
}

/***********************************************************
 Dump the current idmap
 **********************************************************/
static int net_idmap_dump(struct net_context *c, int argc, const char **argv)
{
	struct db_context *db;
	TALLOC_CTX *mem_ctx;

	if ( argc != 1  || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap dump <inputfile>\n"
			   "  Dump current ID mapping.\n"
			   "    inputfile\tTDB file to read mappings from.\n"));
		return c->display_usage?0:-1;
	}

	mem_ctx = talloc_stackframe();

	db = db_open(mem_ctx, argv[0], 0, TDB_DEFAULT, O_RDONLY, 0);
	if (db == NULL) {
		d_fprintf(stderr, _("Could not open idmap db (%s): %s\n"),
			  argv[0], strerror(errno));
		talloc_free(mem_ctx);
		return -1;
	}

	db->traverse_read(db, net_idmap_dump_one_entry, NULL);

	talloc_free(mem_ctx);

	return 0;
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
	char *dbfile = NULL;
	int ret = 0;

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net idmap restore [<inputfile>]\n"
			   "  Restore ID mappings from file\n"
			   "    inputfile\tFile to load ID mappings from. If not "
			   "given, load data from stdin.\n"));
		return 0;
	}

	mem_ctx = talloc_stackframe();

	if (strequal(lp_idmap_backend(), "tdb")) {
		dbfile = state_path("winbindd_idmap.tdb");
		if (dbfile == NULL) {
			d_fprintf(stderr, _("Out of memory!\n"));
			return -1;
		}
	} else if (strequal(lp_idmap_backend(), "tdb2")) {
		dbfile = lp_parm_talloc_string(-1, "tdb", "idmap2.tdb", NULL);
		if (dbfile == NULL) {
			dbfile = talloc_asprintf(mem_ctx, "%s/idmap2.tdb",
						 lp_private_dir());
		}
	} else {
		char *backend, *args;

		backend = talloc_strdup(mem_ctx, lp_idmap_backend());
		args = strchr(backend, ':');
		if (args != NULL) {
			*args = '\0';
		}

		d_printf(_("Sorry, 'net idmap restore' is currently not "
			   "supported for idmap backend = %s.\n"
			   "Only tdb and tdb2 are supported.\n"),
			 backend);

		ret = -1;
		goto done;
	}

	d_fprintf(stderr, _("restoring id mapping to %s data base in '%s'\n"),
		  lp_idmap_backend(), dbfile);

	if (argc == 1) {
		input = fopen(argv[0], "r");
	} else {
		input = stdin;
	}

	db = db_open(mem_ctx, dbfile, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0644);
	if (db == NULL) {
		d_fprintf(stderr, _("Could not open idmap db (%s): %s\n"),
			  dbfile, strerror(errno));
		ret = -1;
		goto done;
	}

	if (db->transaction_start(db) != 0) {
		d_fprintf(stderr, _("Failed to start transaction.\n"));
		ret = -1;
		goto done;
	}

	while (!feof(input)) {
		char line[128], sid_string[128];
		int len;
		unsigned long idval;

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
			ret = dbwrap_store_int32(db, "USER HWM", idval);
			if (ret != 0) {
				d_fprintf(stderr, _("Could not store USER HWM.\n"));
				break;
			}
		} else if (sscanf(line, "GROUP HWM %lu", &idval) == 1) {
			ret = dbwrap_store_int32(db, "GROUP HWM", idval);
			if (ret != 0) {
				d_fprintf(stderr,
					  _("Could not store GROUP HWM.\n"));
				break;
			}
		} else {
			d_fprintf(stderr, _("ignoring invalid line [%s]\n"),
				  line);
			continue;
		}
	}

	if (ret == 0) {
		if(db->transaction_commit(db) != 0) {
			d_fprintf(stderr, _("Failed to commit transaction.\n"));
			ret = -1;
		}
	} else {
		if (db->transaction_cancel(db) != 0) {
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

/***********************************************************
 Delete a SID mapping from a winbindd_idmap.tdb
 **********************************************************/
static int net_idmap_delete(struct net_context *c, int argc, const char **argv)
{
	d_printf("%s\n", _("Not implemented yet"));
	return -1;
}

static int net_idmap_set(struct net_context *c, int argc, const char **argv)
{
	d_printf("%s\n", _("Not implemented yet"));
	return -1;
}
bool idmap_store_secret(const char *backend, bool alloc,
			const char *domain, const char *identity,
			const char *secret)
{
	char *tmp;
	int r;
	bool ret;

	if (alloc) {
		r = asprintf(&tmp, "IDMAP_ALLOC_%s", backend);
	} else {
		r = asprintf(&tmp, "IDMAP_%s_%s", backend, domain);
	}

	if (r < 0) return false;

	strupper_m(tmp); /* make sure the key is case insensitive */
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

	ret = idmap_store_secret("ldap", false, domain, dn, secret);

	if ( ! ret) {
		d_fprintf(stderr, _("Failed to store secret\n"));
		talloc_free(ctx);
		return -1;
	}

	d_printf(_("Secret stored\n"));
	return 0;
}

int net_help_idmap(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("net idmap dump <inputfile>\n"
		   "    Dump current id mapping\n"));

	d_printf(_("net idmap restore\n"
		   "    Restore entries from stdin\n"));

	/* Deliberately *not* document net idmap delete */

	d_printf(_("net idmap secret <DOMAIN>|alloc <secret>\n"
		   "    Set the secret for the specified DOMAIN (or the alloc "
		   "module)\n"));

	return -1;
}

static int net_idmap_aclmapset(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	int result = -1;
	struct dom_sid src_sid, dst_sid;
	char *src, *dst;
	struct db_context *db;
	struct db_record *rec;
	NTSTATUS status;

	if (argc != 3 || c->display_usage) {
		d_fprintf(stderr, "%s net idmap aclmapset <tdb> "
			  "<src-sid> <dst-sid>\n", _("Usage:"));
		return -1;
	}

	if (!(mem_ctx = talloc_init("net idmap aclmapset"))) {
		d_fprintf(stderr, _("talloc_init failed\n"));
		return -1;
	}

	if (!(db = db_open(mem_ctx, argv[0], 0, TDB_DEFAULT,
			   O_RDWR|O_CREAT, 0600))) {
		d_fprintf(stderr, _("db_open failed: %s\n"), strerror(errno));
		goto fail;
	}

	if (!string_to_sid(&src_sid, argv[1])) {
		d_fprintf(stderr, _("%s is not a valid sid\n"), argv[1]);
		goto fail;
	}

	if (!string_to_sid(&dst_sid, argv[2])) {
		d_fprintf(stderr, _("%s is not a valid sid\n"), argv[2]);
		goto fail;
	}

	if (!(src = sid_string_talloc(mem_ctx, &src_sid))
	    || !(dst = sid_string_talloc(mem_ctx, &dst_sid))) {
		d_fprintf(stderr, _("talloc_strdup failed\n"));
		goto fail;
	}

	if (!(rec = db->fetch_locked(
		      db, mem_ctx, string_term_tdb_data(src)))) {
		d_fprintf(stderr, _("could not fetch db record\n"));
		goto fail;
	}

	status = rec->store(rec, string_term_tdb_data(dst), 0);
	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("could not store record: %s\n"),
			  nt_errstr(status));
		goto fail;
	}

	result = 0;
fail:
	TALLOC_FREE(mem_ctx);
	return result;
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
			N_("Not implemented yet"),
			N_("net idmap delete\n"
			   "  Not implemented yet")
		},
		{
			"secret",
			net_idmap_secret,
			NET_TRANSPORT_LOCAL,
			N_("Set secret for specified domain"),
			N_("net idmap secret {<DOMAIN>|alloc} <secret>\n"
			   "  Set secret for specified domain or alloc module")
		},
		{
			"aclmapset",
			net_idmap_aclmapset,
			NET_TRANSPORT_LOCAL,
			N_("Set acl map"),
			N_("net idmap aclmapset\n"
			   "  Set acl map")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net idmap", func);
}


