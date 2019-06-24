/*
   CTDB event daemon

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

#include "common/conf.h"
#include "common/path.h"

#include "event/event_conf.h"

static bool event_conf_validate_debug_script(const char *key,
					     const char *old_script,
					     const char *new_script,
					     enum conf_update_mode mode)
{
	char script[PATH_MAX];
	char script_path[PATH_MAX];
	struct stat st;
	size_t len;
	int ret;

	len = strlcpy(script, new_script, sizeof(script));
	if (len >= sizeof(script)) {
		D_ERR("debug script name too long\n");
		return false;
	}

	ret = snprintf(script_path,
		       sizeof(script_path),
		       "%s/%s",
		       path_etcdir(),
		       basename(script));
	if (ret < 0 || (size_t)ret >= sizeof(script_path)) {
		D_ERR("debug script path too long\n");
		return false;
	}

	ret = stat(script_path, &st);
	if (ret == -1) {
		D_ERR("debug script %s does not exist\n", script_path);
		return false;
	}

	if (! S_ISREG(st.st_mode)) {
		D_ERR("debug script %s is not a file\n", script_path);
		return false;
	}
	if (! (st.st_mode & S_IXUSR)) {
		D_ERR("debug script %s is not executable\n", script_path);
		return false;
	}

	return true;
}

void event_conf_init(struct conf_context *conf)
{
	conf_define_section(conf, EVENT_CONF_SECTION, NULL);

	conf_define_string(conf,
			   EVENT_CONF_SECTION,
			   EVENT_CONF_DEBUG_SCRIPT,
			   NULL,
			   event_conf_validate_debug_script);
}
