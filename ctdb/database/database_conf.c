/*
   CTDB database config handling

   Copyright (C) Martin Schwenke  2018

   database_conf_validate_lock_debug_script() based on
   event_conf_validatye_debug_script():

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
#include "system/dir.h"

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "common/conf.h"
#include "common/path.h"

#include "database_conf.h"

#define DATABASE_CONF_VOLATILE_DB_DIR_DEFAULT   CTDB_VARDIR "/volatile"
#define DATABASE_CONF_PERSISTENT_DB_DIR_DEFAULT CTDB_VARDIR "/persistent"
#define DATABASE_CONF_STATE_DB_DIR_DEFAULT      CTDB_VARDIR "/state"

static bool check_static_string_change(const char *key,
				       const char *old_value,
				       const char *new_value,
				       enum conf_update_mode mode)
{
	if (mode == CONF_MODE_RELOAD) {
		if (strcmp(old_value, new_value) != 0) {
			D_WARNING("Ignoring update of [%s] -> %s\n",
				  DATABASE_CONF_SECTION,
				  key);
		}
	}

	return true;
}

static bool check_static_boolean_change(const char *key,
					bool old_value,
					bool new_value,
					enum conf_update_mode mode)
{
	if (mode == CONF_MODE_RELOAD || CONF_MODE_API) {
		if (old_value != new_value) {
			D_WARNING("Ignoring update of [%s] -> %s\n",
				  DATABASE_CONF_SECTION,
				  key);
		}
	}

	return true;
}

static bool database_conf_validate_lock_debug_script(const char *key,
						     const char *old_script,
						     const char *new_script,
						     enum conf_update_mode mode)
{
	char script[PATH_MAX];
	char script_path[PATH_MAX];
	struct stat st;
	size_t len;
	int ret;

	if (new_script == NULL) {
		return true;
	}

	len = strlcpy(script, new_script, sizeof(script));
	if (len >= sizeof(script)) {
		D_ERR("lock debug script name too long\n");
		return false;
	}

	ret = snprintf(script_path,
		       sizeof(script_path),
		       "%s/%s",
		       path_etcdir(),
		       basename(script));
	if (ret < 0 || (size_t)ret >= sizeof(script_path)) {
		D_ERR("lock debug script path too long\n");
		return false;
	}

	ret = stat(script_path, &st);
	if (ret == -1) {
		D_ERR("lock debug script %s does not exist\n", script_path);
		return false;
	}

	if (! S_ISREG(st.st_mode)) {
		D_ERR("lock debug script %s is not a file\n", script_path);
		return false;
	}
	if (! (st.st_mode & S_IXUSR)) {
		D_ERR("lock debug script %s is not executable\n", script_path);
		return false;
	}

	return true;
}

static bool database_conf_validate_db_dir(const char *key,
					  const char *old_dir,
					  const char *new_dir,
					  enum conf_update_mode mode)
{
	if (! directory_exist(new_dir)) {
		D_ERR("%s \"%s\" does not exist\n", key, new_dir);
		return false;
	}

	/* This sometimes warns but always returns true */
	return check_static_string_change(key, old_dir, new_dir, mode);
}

void database_conf_init(struct conf_context *conf)
{
	conf_define_section(conf, DATABASE_CONF_SECTION, NULL);

	conf_define_string(conf,
			   DATABASE_CONF_SECTION,
			   DATABASE_CONF_VOLATILE_DB_DIR,
			   DATABASE_CONF_VOLATILE_DB_DIR_DEFAULT,
			   database_conf_validate_db_dir);
	conf_define_string(conf,
			   DATABASE_CONF_SECTION,
			   DATABASE_CONF_PERSISTENT_DB_DIR,
			   DATABASE_CONF_PERSISTENT_DB_DIR_DEFAULT,
			   database_conf_validate_db_dir);
	conf_define_string(conf,
			   DATABASE_CONF_SECTION,
			   DATABASE_CONF_STATE_DB_DIR,
			   DATABASE_CONF_STATE_DB_DIR_DEFAULT,
			   database_conf_validate_db_dir);
	conf_define_string(conf,
			   DATABASE_CONF_SECTION,
			   DATABASE_CONF_LOCK_DEBUG_SCRIPT,
			   NULL,
			   database_conf_validate_lock_debug_script);
	conf_define_boolean(conf,
			    DATABASE_CONF_SECTION,
			    DATABASE_CONF_TDB_MUTEXES,
			    true,
			    check_static_boolean_change);
}
