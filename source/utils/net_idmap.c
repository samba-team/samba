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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "includes.h"
#include "utils/net.h"

#define ALLOC_CHECK(mem) do { \
	if (!mem) { \
		d_fprintf(stderr, "Out of memory!\n"); \
		talloc_free(ctx); \
		return -1; \
	} } while(0)

/***********************************************************
 Helper function for net_idmap_dump. Dump one entry.
 **********************************************************/
static int net_idmap_dump_one_entry(TDB_CONTEXT *tdb,
				    TDB_DATA key,
				    TDB_DATA data,
				    void *unused)
{
	if (strcmp((char *)key.dptr, "USER HWM") == 0) {
		printf("USER HWM %d\n", IVAL(data.dptr,0));
		return 0;
	}

	if (strcmp((char *)key.dptr, "GROUP HWM") == 0) {
		printf("GROUP HWM %d\n", IVAL(data.dptr,0));
		return 0;
	}

	if (strncmp((char *)key.dptr, "S-", 2) != 0)
		return 0;

	printf("%s %s\n", data.dptr, key.dptr);
	return 0;
}

/***********************************************************
 Dump the current idmap
 **********************************************************/
static int net_idmap_dump(int argc, const char **argv)
{
	TDB_CONTEXT *idmap_tdb;

	if ( argc != 1 )
		return net_help_idmap( argc, argv );

	idmap_tdb = tdb_open_log(argv[0], 0, TDB_DEFAULT, O_RDONLY, 0);

	if (idmap_tdb == NULL) {
		d_fprintf(stderr, "Could not open idmap: %s\n", argv[0]);
		return -1;
	}

	tdb_traverse(idmap_tdb, net_idmap_dump_one_entry, NULL);

	tdb_close(idmap_tdb);

	return 0;
}

/***********************************************************
 Write entries from stdin to current local idmap
 **********************************************************/

static int net_idmap_restore(int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	FILE *input;

	if (! winbind_ping()) {
		d_fprintf(stderr, "To use net idmap Winbindd must be running.\n");
		return -1;
	}

	ctx = talloc_new(NULL);
	ALLOC_CHECK(ctx);

	if (argc == 1) {
		input = fopen(argv[0], "r");
	} else {
		input = stdin;
	}

	while (!feof(input)) {
		char line[128], sid_string[128];
		int len;
		struct wbcDomainSid sid;
		enum id_type type = ID_TYPE_NOT_SPECIFIED;
		unsigned long idval;
		wbcErr wbc_status;

		if (fgets(line, 127, input) == NULL)
			break;

		len = strlen(line);

		if ( (len > 0) && (line[len-1] == '\n') )
			line[len-1] = '\0';

		if (sscanf(line, "GID %lu %128s", &idval, sid_string) == 2) {
			type = ID_TYPE_GID;
		} else if (sscanf(line, "UID %lu %128s", &idval, sid_string) == 2) {
			type = ID_TYPE_UID;
		} else if (sscanf(line, "USER HWM %lu", &idval) == 1) {
			/* set uid hwm */
			wbc_status = wbcSetUidHwm(idval);
			if (!WBC_ERROR_IS_OK(wbc_status)) {
				d_fprintf(stderr, "Could not set USER HWM: %s\n",
					  wbcErrorString(wbc_status));
			}
			continue;
		} else if (sscanf(line, "GROUP HWM %lu", &idval) == 1) {
			/* set gid hwm */
			wbc_status = wbcSetGidHwm(idval);
			if (!WBC_ERROR_IS_OK(wbc_status)) {
				d_fprintf(stderr, "Could not set GROUP HWM: %s\n",
					  wbcErrorString(wbc_status));
			}
			continue;
		} else {
			d_fprintf(stderr, "ignoring invalid line [%s]\n", line);
			continue;
		}

		wbc_status = wbcStringToSid(sid_string, &sid);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			d_fprintf(stderr, "ignoring invalid sid [%s]: %s\n",
				  sid_string, wbcErrorString(wbc_status));
			continue;
		}

		if (type == ID_TYPE_UID) {
			wbc_status = wbcSetUidMapping(idval, &sid);
		} else {
			wbc_status = wbcSetGidMapping(idval, &sid);
		}
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			d_fprintf(stderr, "Could not set mapping of %s %lu to sid %s: %s\n",
				 (type == ID_TYPE_GID) ? "GID" : "UID",
				 idval, sid_string,
				 wbcErrorString(wbc_status));
			continue;
		}
	}

	if (input != stdin) {
		fclose(input);
	}

	talloc_free(ctx);
	return 0;
}

/***********************************************************
 Delete a SID mapping from a winbindd_idmap.tdb
 **********************************************************/
static int net_idmap_delete(int argc, const char **argv)
{
	d_printf("Not Implemented yet\n");
	return -1;
}

static int net_idmap_set(int argc, const char **argv)
{
	d_printf("Not Implemented yet\n");
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


static int net_idmap_secret(int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	const char *secret;
	const char *dn;
	char *domain;
	char *backend;
	char *opt = NULL;
	bool ret;

	if (argc != 2) {
		return net_help_idmap(argc, argv);
	}

	secret = argv[1];

	ctx = talloc_new(NULL);
	ALLOC_CHECK(ctx);

	if (strcmp(argv[0], "alloc") == 0) {
		domain = NULL;
		backend = lp_idmap_alloc_backend();
	} else {
		domain = talloc_strdup(ctx, argv[0]);
		ALLOC_CHECK(domain);

		opt = talloc_asprintf(ctx, "idmap config %s", domain);
		ALLOC_CHECK(opt);

		backend = talloc_strdup(ctx, lp_parm_const_string(-1, opt, "backend", "tdb"));
		ALLOC_CHECK(backend);
	}

	if ( ( ! backend) || ( ! strequal(backend, "ldap"))) {
		d_fprintf(stderr, "The only currently supported backend is LDAP\n");
		talloc_free(ctx);
		return -1;
	}

	if (domain) {

		dn = lp_parm_const_string(-1, opt, "ldap_user_dn", NULL);
		if ( ! dn) {
			d_fprintf(stderr, "Missing ldap_user_dn option for domain %s\n", domain);
			talloc_free(ctx);
			return -1;
		}

		ret = idmap_store_secret("ldap", false, domain, dn, secret);
	} else {
		dn = lp_parm_const_string(-1, "idmap alloc config", "ldap_user_dn", NULL);
		if ( ! dn) {
			d_fprintf(stderr, "Missing ldap_user_dn option for alloc backend\n");
			talloc_free(ctx);
			return -1;
		}

		ret = idmap_store_secret("ldap", true, NULL, dn, secret);
	}

	if ( ! ret) {
		d_fprintf(stderr, "Failed to store secret\n");
		talloc_free(ctx);
		return -1;
	}

	d_printf("Secret stored\n");
	return 0;
}

int net_help_idmap(int argc, const char **argv)
{
	d_printf("net idmap dump <inputfile>\n"\
		 "    Dump current id mapping\n");

	d_printf("net idmap restore\n"\
		 "    Restore entries from stdin\n");

	/* Deliberately *not* document net idmap delete */

	d_printf("net idmap secret <DOMAIN>|alloc <secret>\n"\
		 "    Set the secret for the specified DOMAIN (or the alloc module)\n");

	return -1;
}

static int net_idmap_aclmapset(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	int result = -1;
	DOM_SID src_sid, dst_sid;
	char *src, *dst;
	struct db_context *db;
	struct db_record *rec;
	NTSTATUS status;

	if (argc != 3) {
		d_fprintf(stderr, "usage: net idmap aclmapset <tdb> "
			  "<src-sid> <dst-sid>\n");
		return -1;
	}

	if (!(mem_ctx = talloc_init("net idmap aclmapset"))) {
		d_fprintf(stderr, "talloc_init failed\n");
		return -1;
	}

	if (!(db = db_open(mem_ctx, argv[0], 0, TDB_DEFAULT,
			   O_RDWR|O_CREAT, 0600))) {
		d_fprintf(stderr, "db_open failed: %s\n", strerror(errno));
		goto fail;
	}

	if (!string_to_sid(&src_sid, argv[1])) {
		d_fprintf(stderr, "%s is not a valid sid\n", argv[1]);
		goto fail;
	}

	if (!string_to_sid(&dst_sid, argv[2])) {
		d_fprintf(stderr, "%s is not a valid sid\n", argv[2]);
		goto fail;
	}

	if (!(src = sid_string_talloc(mem_ctx, &src_sid))
	    || !(dst = sid_string_talloc(mem_ctx, &dst_sid))) {
		d_fprintf(stderr, "talloc_strdup failed\n");
		goto fail;
	}

	if (!(rec = db->fetch_locked(
		      db, mem_ctx, string_term_tdb_data(src)))) {
		d_fprintf(stderr, "could not fetch db record\n");
		goto fail;
	}

	status = rec->store(rec, string_term_tdb_data(dst), 0);
	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "could not store record: %s\n",
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
int net_idmap(int argc, const char **argv)
{
	struct functable func[] = {
		{"dump", net_idmap_dump},
		{"restore", net_idmap_restore},
		{"setmap", net_idmap_set },
		{"delete", net_idmap_delete},
		{"secret", net_idmap_secret},
		{"aclmapset", net_idmap_aclmapset},
		{"help", net_help_idmap},
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_help_idmap);
}


