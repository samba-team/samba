/*
   Unix SMB/CIFS implementation.
   simple ldb tdb dump util
   Copyright (C) Andrew Tridgell              2001
   Copyright (C) Andrew Bartlett              2012

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

#include "replace.h"
#include "system/locale.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/wait.h"
#include <tdb.h>
#include <ldb.h>
#include <ldb_private.h>

#ifdef HAVE_LMDB
#include <lmdb.h>
#endif /* ifdef HAVE_LMDB */


static struct ldb_context *ldb;
bool show_index = false;
bool validate_contents = false;

static void print_data(TDB_DATA d)
{
	unsigned char *p = (unsigned char *)d.dptr;
	int len = d.dsize;
	while (len--) {
		if (isprint(*p) && !strchr("\"\\", *p)) {
			fputc(*p, stdout);
		} else {
			printf("\\%02X", *p);
		}
		p++;
	}
}

static unsigned int pull_uint32(uint8_t *p)
{
       return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}


static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA _dbuf, void *state)
{
	int ret, i, j;
	struct ldb_dn *dn = state;
	struct ldb_message *msg = ldb_msg_new(NULL);
	struct ldb_val dbuf = {
		.data = _dbuf.dptr,
		.length = _dbuf.dsize,
	};
	struct ldb_ldif ldif = {
		.msg = msg,
		.changetype = LDB_CHANGETYPE_NONE
	};
	if (!msg) {
		return -1;
	}

	ret = ldb_unpack_data(ldb, &dbuf, msg);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse record %*.*s as an LDB record\n", (int)key.dsize, (int)key.dsize, (char *)key.dptr);
		TALLOC_FREE(msg);
		return 0;
	}

	if (dn && ldb_dn_compare(msg->dn, dn) != 0) {
		TALLOC_FREE(msg);
		return 0;
	}

	if (!show_index && ldb_dn_is_special(msg->dn)) {
		const char *dn_lin = ldb_dn_get_linearized(msg->dn);
		if ((strcmp(dn_lin, "@BASEINFO") == 0) || (strncmp(dn_lin, "@INDEX:", strlen("@INDEX:")) == 0)) {
			/*
			  the user has asked not to show index
			  records. Also exclude BASEINFO as it
			  contains meta-data which will be re-created
			  if this database is restored
			 */
			TALLOC_FREE(msg);
			return 0;
		}
	}

	printf("# key: ");
	print_data(key);
	printf("\n# pack format: %#010x\n", pull_uint32(_dbuf.dptr));

	if (!validate_contents || ldb_dn_is_special(msg->dn)) {
		ldb_ldif_write_file(ldb, stdout, &ldif);
		TALLOC_FREE(msg);
		return 0;
	}

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_schema_attribute *a;

		a = ldb_schema_attribute_by_name(ldb, msg->elements[i].name);
		for (j=0;j<msg->elements[i].num_values;j++) {
			struct ldb_val v;
			ret = a->syntax->ldif_write_fn(ldb, msg, &msg->elements[i].values[j], &v);
			if (ret != 0) {
				v = msg->elements[i].values[j];
				if (ldb_should_b64_encode(ldb, &v)) {
					v.data = (uint8_t *)ldb_base64_encode(ldb, (char *)v.data, v.length);
					v.length = strlen((char *)v.data);
				}
				fprintf(stderr, "On %s element %s value %d (%*.*s) failed to convert to LDIF correctly, skipping possibly corrupt record\n",
					ldb_dn_get_linearized(msg->dn),
					msg->elements[i].name,
					j, (int)v.length, (int)v.length,
					v.data);
				TALLOC_FREE(msg);
				return 0;
			}
		}
	}
	ldb_ldif_write_file(ldb, stdout, &ldif);
	TALLOC_FREE(msg);

	return 0;
}

static void log_stderr(struct tdb_context *tdb, enum tdb_debug_level level,
		       const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

static void log_stderr(struct tdb_context *tdb, enum tdb_debug_level level,
		       const char *fmt, ...)
{
	va_list ap;
	const char *name = tdb_name(tdb);
	const char *prefix = "";

	if (!name)
		name = "unnamed";

	switch (level) {
	case TDB_DEBUG_ERROR:
		prefix = "ERROR: ";
		break;
	case TDB_DEBUG_WARNING:
		prefix = "WARNING: ";
		break;
	case TDB_DEBUG_TRACE:
		return;

	default:
	case TDB_DEBUG_FATAL:
		prefix = "FATAL: ";
		break;
	}

	va_start(ap, fmt);
	fprintf(stderr, "tdb(%s): %s", name, prefix);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void emergency_walk(TDB_DATA key, TDB_DATA dbuf, void *keyname)
{
	traverse_fn(NULL, key, dbuf, keyname);
}

static int dump_tdb(const char *fname, struct ldb_dn *dn, bool emergency)
{
	TDB_CONTEXT *tdb;
	struct tdb_logging_context logfn = {
		.log_fn = log_stderr,
	};

	tdb = tdb_open_ex(fname, 0, 0, O_RDONLY, 0, &logfn, NULL);
	if (!tdb) {
		fprintf(stderr, "Failed to open %s\n", fname);
		return 1;
	}

	if (emergency) {
		return tdb_rescue(tdb, emergency_walk, dn) == 0;
	}
	return tdb_traverse(tdb, traverse_fn, dn) == -1 ? 1 : 0;
}

#ifdef HAVE_LMDB
static int dump_lmdb(const char *fname, struct ldb_dn *dn, bool emergency)
{
	int ret;
	struct MDB_env *env = NULL;
	struct MDB_txn *txn = NULL;
	MDB_dbi dbi;
	struct MDB_cursor *cursor = NULL;
	struct MDB_val key;
	struct MDB_val data;

	ret = mdb_env_create(&env);
	if (ret != 0) {
		fprintf(stderr,
			"Could not create MDB environment: (%d)  %s\n",
			ret,
			mdb_strerror(ret));
		goto close_env;
	}

	ret = mdb_env_open(env,
			   fname,
			   MDB_NOSUBDIR|MDB_NOTLS|MDB_RDONLY,
			   0600);
	if (ret != 0) {
		fprintf(stderr,
			"Could not open environment for %s: (%d)  %s\n",
			fname,
			ret,
			mdb_strerror(ret));
		goto close_env;
	}

	ret = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (ret != 0) {
		fprintf(stderr,
			"Could not start transaction: (%d)  %s\n",
			ret,
			mdb_strerror(ret));
		goto close_env;
	}

	ret = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (ret != 0) {
		fprintf(stderr,
			"Could not open database: (%d)  %s\n",
			ret,
			mdb_strerror(ret));
		goto close_txn;
	}

	ret = mdb_cursor_open(txn, dbi, &cursor);
	if (ret != 0) {
		fprintf(stderr,
			"Could not open cursor: (%d)  %s\n",
			ret,
			mdb_strerror(ret));
		goto close_txn;
	}

	ret = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
	if (ret != 0 && ret != MDB_NOTFOUND) {
		fprintf(stderr,
			"Could not find first record: (%d)  %s\n",
			ret,
			mdb_strerror(ret));
		goto close_cursor;
	}
	while (ret != MDB_NOTFOUND) {
		struct TDB_DATA tkey = {
			.dptr = key.mv_data,
			.dsize = key.mv_size
		};
		struct TDB_DATA tdata = {
			.dptr = data.mv_data,
			.dsize = data.mv_size
		};
		traverse_fn(NULL, tkey, tdata, dn);
		ret = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
		if (ret != 0 && ret != MDB_NOTFOUND) {
			fprintf(stderr,
				"Could not read next record: (%d)  %s\n",
				ret,
				mdb_strerror(ret));
			goto close_cursor;
		}
	}
	ret = 0;

close_cursor:
	mdb_cursor_close(cursor);
close_txn:
	mdb_txn_commit(txn);
close_env:
	mdb_env_close(env);

	if (ret != 0) {
		return 1;
	}
	return 0;

}
#else
static int dump_lmdb(const char *fname, struct ldb_dn *dn, bool emergency)
{
	/* not built with lmdb support */
	return 1;
}
#endif /* #ifdef HAVE_LMDB */

static void usage( void)
{
	printf( "Usage: ldbdump [options] <filename>\n\n");
	printf( "   -h          this help message\n");
	printf( "   -d DN       dumps DN only\n");
	printf( "   -e          emergency dump, for corrupt databases\n");
	printf( "   -i          include index and @BASEINFO records in dump\n");
	printf( "   -c          validate contents of the records\n");
}

 int main(int argc, char *argv[])
{
	bool emergency = false;
	int c, rc;
	char *fname;
	struct ldb_dn *dn = NULL;

	ldb = ldb_init(NULL, NULL);
	if (ldb == NULL) {
		fprintf(stderr, "ldb: ldb_init failed()");
		exit(1);
	}

	rc = ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_PRECONNECT);
	if (rc != LDB_SUCCESS) {
		fprintf(stderr, "ldb: failed to run preconnect hooks (needed to get Samba LDIF handlers): %s\n", ldb_strerror(rc));
		exit(1);
	}

	if (argc < 2) {
		printf("Usage: ldbdump <fname>\n");
		exit(1);
	}

	while ((c = getopt( argc, argv, "hd:eic")) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit( 0);
		case 'd':
			dn = ldb_dn_new(ldb, ldb, optarg);
			if (!dn) {
				fprintf(stderr, "ldb failed to parse %s as a DN\n", optarg);
				exit(1);
			}
			break;
		case 'e':
			emergency = true;
			break;
		case 'i':
			show_index = true;
			break;
		case 'c':
			validate_contents = true;
			break;
		default:
			usage();
			exit( 1);
		}
	}

	fname = argv[optind];

	rc = dump_lmdb(fname, dn, emergency);
	if (rc != 0) {
		rc = dump_tdb(fname, dn, emergency);
		if (rc != 0) {
			fprintf(stderr, "Failed to open %s\n", fname);
			return 1;
		}
	}
	return 0;

}
