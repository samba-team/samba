/*
   Construct runtime paths

   Copyright (C) Amitay Isaacs  2018

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

#include "replace.h"
#include "system/filesys.h"

#include "lib/util/debug.h"

#include "common/path.h"

#define CTDB_CONFIG_FILE	"ctdb.conf"

struct {
	char *basedir;
	char datadir[PATH_MAX];
	char etcdir[PATH_MAX];
	char rundir[PATH_MAX];
	char vardir[PATH_MAX];
	bool test_mode;
	bool basedir_set;
	bool datadir_set;
	bool etcdir_set;
	bool rundir_set;
	bool vardir_set;
} ctdb_paths = {
	.datadir = CTDB_DATADIR,
	.etcdir = CTDB_ETCDIR,
	.rundir = CTDB_RUNDIR,
	.vardir = CTDB_VARDIR,
};

static void path_set_basedir(void)
{
	const char *t;

	t = getenv("CTDB_TEST_MODE");
	if (t == NULL) {
		goto done;
	}

	ctdb_paths.test_mode = true;

	ctdb_paths.basedir = getenv("CTDB_BASE");
	if (ctdb_paths.basedir == NULL) {
		D_ERR("Broken CTDB setup, CTDB_BASE not set in test mode\n");
		abort();
	}

done:
	ctdb_paths.basedir_set = true;
}

static bool path_construct(char *path, const char *subdir)
{
	char p[PATH_MAX];
	int len;

	if (! ctdb_paths.basedir_set) {
		path_set_basedir();
	}

	if (! ctdb_paths.test_mode) {
		return true;
	}

	if (subdir == NULL) {
		len = snprintf(p, sizeof(p), "%s", ctdb_paths.basedir);
	} else {
		len = snprintf(p,
			       sizeof(p),
			       "%s/%s",
			       ctdb_paths.basedir,
			       subdir);
	}

	if ((size_t)len >= sizeof(p)) {
		return false;
	}

	strncpy(path, p, PATH_MAX);
	return true;
}

const char *path_datadir(void)
{
	bool ok;

	if (! ctdb_paths.datadir_set) {
		ok = path_construct(ctdb_paths.datadir, "share");
		if (!ok) {
			D_ERR("Failed to construct DATADIR\n");
		} else {
			ctdb_paths.datadir_set = true;
		}
	}

	return ctdb_paths.datadir;
}

const char *path_etcdir(void)
{
	bool ok;

	if (! ctdb_paths.etcdir_set) {
		ok = path_construct(ctdb_paths.etcdir, NULL);
		if (!ok) {
			D_ERR("Failed to construct ETCDIR\n");
		} else {
			ctdb_paths.etcdir_set = true;
		}
	}

	return ctdb_paths.etcdir;
}

const char *path_rundir(void)
{
	bool ok;

	if (! ctdb_paths.rundir_set) {
		ok = path_construct(ctdb_paths.rundir, "run");
		if (!ok) {
			D_ERR("Failed to construct RUNDIR\n");
		} else {
			ctdb_paths.rundir_set = true;
		}
	}

	return ctdb_paths.rundir;
}

const char *path_vardir(void)
{
	bool ok;

	if (! ctdb_paths.vardir_set) {
		ok = path_construct(ctdb_paths.vardir, "var");
		if (!ok) {
			D_ERR("Failed to construct VARDIR\n");
		} else {
			ctdb_paths.vardir_set = true;
		}
	}

	return ctdb_paths.vardir;
}

char *path_datadir_append(TALLOC_CTX *mem_ctx, const char *path)
{
	return talloc_asprintf(mem_ctx, "%s/%s", path_datadir(), path);
}

char *path_etcdir_append(TALLOC_CTX *mem_ctx, const char *path)
{
	return talloc_asprintf(mem_ctx, "%s/%s", path_etcdir(), path);
}

char *path_rundir_append(TALLOC_CTX *mem_ctx, const char *path)
{
	return talloc_asprintf(mem_ctx, "%s/%s", path_rundir(), path);
}

char *path_vardir_append(TALLOC_CTX *mem_ctx, const char *path)
{
	return talloc_asprintf(mem_ctx, "%s/%s", path_vardir(), path);
}

char *path_config(TALLOC_CTX *mem_ctx)
{
	return path_etcdir_append(mem_ctx, CTDB_CONFIG_FILE);
}

char *path_socket(TALLOC_CTX *mem_ctx, const char *daemon)
{
	if (strcmp(daemon, "ctdbd") == 0) {
		const char *t = getenv("CTDB_SOCKET");

		if (t != NULL) {
			return talloc_strdup(mem_ctx, t);
		}
	}

	return talloc_asprintf(mem_ctx,
			       "%s/%s.socket",
			       path_rundir(),
			       daemon);
}

char *path_pidfile(TALLOC_CTX *mem_ctx, const char *daemon)
{
	return talloc_asprintf(mem_ctx,
			       "%s/%s.pid",
			       path_rundir(),
			       daemon);
}
