/*
   Unix SMB/CIFS implementation.
   low level tdb backup and restore utility
   Copyright (C) Andrew Tridgell              2002

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

/*

  This program is meant for backup/restore of tdb databases. Typical usage would be:
     tdbbackup *.tdb
  when Samba shuts down cleanly, which will make a backup of all the local databases
  to *.bak files. Then on Samba startup you would use:
     tdbbackup -v *.tdb
  and this will check the databases for corruption and if corruption is detected then
  the backup will be restored.

  You may also like to do a backup on a regular basis while Samba is
  running, perhaps using cron.

  The reason this program is needed is to cope with power failures
  while Samba is running. A power failure could lead to database
  corruption and Samba will then not start correctly.

  Note that many of the databases in Samba are transient and thus
  don't need to be backed up, so you can optimise the above a little
  by only running the backup on the critical databases.

 */

#include "config.h"
#include "tdb2.h"
#include "system/filesys.h"

/* Currently we default to creating a tdb1.  This will change! */
#define TDB2_IS_DEFAULT false

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

static int failed;

static void tdb_log(struct tdb_context *tdb,
		    enum tdb_log_level level,
		    enum TDB_ERROR ecode,
		    const char *message,
		    void *data)
{
	fprintf(stderr, "%s:%s\n", tdb_errorstr(ecode), message);
}

static char *add_suffix(const char *name, const char *suffix)
{
	char *ret;
	int len = strlen(name) + strlen(suffix) + 1;
	ret = (char *)malloc(len);
	if (!ret) {
		fprintf(stderr,"Out of memory!\n");
		exit(1);
	}
	snprintf(ret, len, "%s%s", name, suffix);
	return ret;
}

static int copy_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	struct tdb_context *tdb_new = (struct tdb_context *)state;
	enum TDB_ERROR err;

	err = tdb_store(tdb_new, key, dbuf, TDB_INSERT);
	if (err) {
		fprintf(stderr,"Failed to insert into %s: %s\n",
			tdb_name(tdb_new), tdb_errorstr(err));
		failed = 1;
		return 1;
	}
	return 0;
}


static int test_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	return 0;
}

/*
  carefully backup a tdb, validating the contents and
  only doing the backup if its OK
  this function is also used for restore
*/
static int backup_tdb(const char *old_name, const char *new_name,
		      bool tdb2, int hash_size)
{
	struct tdb_context *tdb;
	struct tdb_context *tdb_new;
	char *tmp_name;
	struct stat st;
	int count1, count2;
	enum TDB_ERROR err;
	union tdb_attribute log_attr, hsize_attr;
	int tdb_flags = TDB_DEFAULT;

	if (!tdb2) {
		tdb_flags |= TDB_VERSION1;
	}

	tmp_name = add_suffix(new_name, ".tmp");

	/* stat the old tdb to find its permissions */
	if (stat(old_name, &st) != 0) {
		perror(old_name);
		free(tmp_name);
		return 1;
	}

	log_attr.base.attr = TDB_ATTRIBUTE_LOG;
	log_attr.base.next = NULL;
	log_attr.log.fn = tdb_log;

	/* open the old tdb */
	tdb = tdb_open(old_name, TDB_DEFAULT, O_RDWR, 0, &log_attr);
	if (!tdb) {
		printf("Failed to open %s\n", old_name);
		free(tmp_name);
		return 1;
	}

	/* create the new tdb */
	if (!tdb2 && hash_size) {
		hsize_attr.base.attr = TDB_ATTRIBUTE_TDB1_HASHSIZE;
		hsize_attr.base.next = NULL;
		hsize_attr.tdb1_hashsize.hsize = hash_size;
		log_attr.base.next = &hsize_attr;
	}

	unlink(tmp_name);
	tdb_new = tdb_open(tmp_name, tdb_flags,
			   O_RDWR|O_CREAT|O_EXCL, st.st_mode & 0777,
			   &log_attr);
	if (!tdb_new) {
		perror(tmp_name);
		free(tmp_name);
		return 1;
	}

	err = tdb_transaction_start(tdb);
	if (err) {
		fprintf(stderr, "Failed to start transaction on old tdb: %s\n",
			tdb_errorstr(err));
		tdb_close(tdb);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* lock the backup tdb so that nobody else can change it */
	err = tdb_lockall(tdb_new);
	if (err) {
		fprintf(stderr, "Failed to lock backup tdb: %s\n",
			tdb_errorstr(err));
		tdb_close(tdb);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	failed = 0;

	/* traverse and copy */
	count1 = tdb_traverse(tdb, copy_fn, (void *)tdb_new);
	if (count1 < 0 || failed) {
		fprintf(stderr,"failed to copy %s\n", old_name);
		tdb_close(tdb);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* close the old tdb */
	tdb_close(tdb);

	/* copy done, unlock the backup tdb */
	tdb_unlockall(tdb_new);

#ifdef HAVE_FDATASYNC
	if (fdatasync(tdb_fd(tdb_new)) != 0) {
#else
	if (fsync(tdb_fd(tdb_new)) != 0) {
#endif
		/* not fatal */
		fprintf(stderr, "failed to fsync backup file\n");
	}

	/* close the new tdb and re-open read-only */
	tdb_close(tdb_new);

	/* we don't need the hash attr any more */
	log_attr.base.next = NULL;

	tdb_new = tdb_open(tmp_name, TDB_DEFAULT, O_RDONLY, 0, &log_attr);
	if (!tdb_new) {
		fprintf(stderr,"failed to reopen %s\n", tmp_name);
		unlink(tmp_name);
		perror(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* traverse the new tdb to confirm */
	count2 = tdb_traverse(tdb_new, test_fn, NULL);
	if (count2 != count1) {
		fprintf(stderr,"failed to copy %s\n", old_name);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* close the new tdb and rename it to .bak */
	tdb_close(tdb_new);
	if (rename(tmp_name, new_name) != 0) {
		perror(new_name);
		free(tmp_name);
		return 1;
	}

	free(tmp_name);

	return 0;
}

/*
  verify a tdb and if it is corrupt then restore from *.bak
*/
static int verify_tdb(const char *fname, const char *bak_name)
{
	struct tdb_context *tdb;
	int count = -1;
	union tdb_attribute log_attr;

	log_attr.base.attr = TDB_ATTRIBUTE_LOG;
	log_attr.base.next = NULL;
	log_attr.log.fn = tdb_log;

	/* open the tdb */
	tdb = tdb_open(fname, TDB_DEFAULT, O_RDONLY, 0, &log_attr);

	/* traverse the tdb, then close it */
	if (tdb) {
		count = tdb_traverse(tdb, test_fn, NULL);
		tdb_close(tdb);
	}

	/* count is < 0 means an error */
	if (count < 0) {
		printf("restoring %s\n", fname);
		return backup_tdb(bak_name, fname, TDB2_IS_DEFAULT, 0);
	}

	printf("%s : %d records\n", fname, count);

	return 0;
}

/*
  see if one file is newer than another
*/
static int file_newer(const char *fname1, const char *fname2)
{
	struct stat st1, st2;
	if (stat(fname1, &st1) != 0) {
		return 0;
	}
	if (stat(fname2, &st2) != 0) {
		return 1;
	}
	return (st1.st_mtime > st2.st_mtime);
}

static void usage(void)
{
	printf("Usage: tdbbackup [options] <fname...>\n\n");
	printf("   -h            this help message\n");
	printf("   -1            make the backup a TDB1 file\n");
	printf("   -2            make the backup a TDB2 file\n");
	printf("   -v            verify mode (restore if corrupt)\n");
	printf("   -s suffix     set the backup suffix\n");
	printf("   -v            verify mode (restore if corrupt)\n");
	printf("   -n hashsize   set the new hash size for the backup\n");
}


 int main(int argc, char *argv[])
{
	int i;
	int ret = 0;
	int c;
	int verify = 0;
	int hashsize = 0;
	bool tdb2 = TDB2_IS_DEFAULT;
	const char *suffix = ".bak";

	while ((c = getopt(argc, argv, "vhs:n:12")) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			verify = 1;
			break;
		case '1':
			tdb2 = false;
			break;
		case '2':
			tdb2 = true;
			break;
		case 's':
			suffix = optarg;
			break;
		case 'n':
			hashsize = atoi(optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage();
		exit(1);
	}

	for (i=0; i<argc; i++) {
		const char *fname = argv[i];
		char *bak_name;

		bak_name = add_suffix(fname, suffix);

		if (verify) {
			if (verify_tdb(fname, bak_name) != 0) {
				ret = 1;
			}
		} else {
			if (file_newer(fname, bak_name) &&
			    backup_tdb(fname, bak_name, tdb2, hashsize) != 0) {
				ret = 1;
			}
		}

		free(bak_name);
	}

	return ret;
}
