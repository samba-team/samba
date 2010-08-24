/*
   database code for libctdb

   Copyright (C) Rusty Russell 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include <unistd.h>
#include <err.h>
#include <talloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include "utils.h"
#include "log.h"
#include "ctdb-test.h"
#include <tdb.h>
#include <ctdb_protocol.h>

/* FIXME */
#define DB_PATH "/tmp/ctdbd-test/dbs/"

static int check_header(TDB_DATA key, TDB_DATA data, void *unused)
{
	struct ctdb_ltdb_header *hdr = (void *)data.dptr;
	if (data.dsize < sizeof(*hdr)) {
		log_line(LOG_ALWAYS, "tdb entry '%.*s' is truncated",
			 key.dsize, key.dptr);
		return -1;
	}
	/* Currently a single-node cluster. */
	if (hdr->dmaster != 0) {
		log_line(LOG_ALWAYS, "tdb entry '%.*s' dmaster %u",
			 key.dsize, key.dptr, hdr->dmaster);
		return -1;
	}
	/* Currently a single-node cluster. */
	if (hdr->laccessor != 0) {
		log_line(LOG_ALWAYS, "tdb entry '%.*s' laccessor %u",
			 key.dsize, key.dptr, hdr->laccessor);
		return -1;
	}
	return 0;
}

static void check_database(const char *name)
{
	struct tdb_context *tdb = tdb_open(name, 0, TDB_DEFAULT, O_RDWR, 0);
	if (!tdb)
		err(1, "Opening tdb %s", name);

	if (tdb_check(tdb, check_header, NULL) != 0) {
		log_line(LOG_ALWAYS, "tdb %s is corrupt", name);
		exit(EXIT_FAILURE);
	}
	tdb_close(tdb);
}

void check_databases(void)
{
	struct dirent *ent;
	DIR *d = opendir(DB_PATH);
	if (!d)
		err(1, "Reading directory %s", DB_PATH);

	while ((ent = readdir(d)) != NULL) {
		if (strends(ent->d_name, ".tdb.0")) {
			char *fullpath = talloc_asprintf(NULL, "%s/%s",
							 DB_PATH, ent->d_name);
			check_database(fullpath);
			talloc_free(fullpath);
		}
	}
	closedir(d);
}

/* FIXME: We assume we don't need locks here.  Not a solid assumption! */
void *save_databases(void)
{
	struct tdb_context *tdb = tdb_open(NULL, 0, TDB_INTERNAL, 0, 0);
	struct dirent *ent;
	DIR *d = opendir(DB_PATH);
	if (!d)
		err(1, "Reading directory %s", DB_PATH);

	while ((ent = readdir(d)) != NULL) {
		if (strends(ent->d_name, ".tdb.0")) {
			TDB_DATA data, key;
			int fd;
			char *fullpath = talloc_asprintf(NULL, "%s/%s",
							 DB_PATH, ent->d_name);
			fd = open(fullpath, O_RDONLY);
			if (fd < 0)
				err(1, "Saving tdb %s", fullpath);
			data.dptr = grab_fd(fd, &data.dsize);
			key.dptr = (void *)fullpath;
			key.dsize = strlen(fullpath) + 1;
			tdb_store(tdb, key, data, TDB_INSERT);
			talloc_free(fullpath);
			close(fd);
		}
	}
	closedir(d);
	return tdb;
}

void restore_databases(void *_tdb)
{
	struct tdb_context *tdb = _tdb;
	TDB_DATA key, data;

	for (key = tdb_firstkey(tdb); key.dptr; key = tdb_nextkey(tdb, key)) {
		int fd = open((char *)key.dptr, O_WRONLY);
		if (fd < 0)
			err(1, "Restoring tdb %s", (char *)key.dptr);
		data = tdb_fetch(tdb, key);
		write(fd, data.dptr, data.dsize);
		free(data.dptr);
		close(fd);
	}
	tdb_close(tdb);
}
