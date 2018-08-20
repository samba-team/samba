/*
   CTDB legacy config handling

   Copyright (C) Martin Schwenke  2018

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

#include "lib/util/debug.h"

#include "common/conf.h"
#include "common/logging.h"

#include "legacy_conf.h"

#define LEGACY_SCRIPT_LOG_LEVEL_DEFAULT "ERROR"

static bool legacy_conf_validate_script_log_level(const char *key,
						  const char *old_loglevel,
						  const char *new_loglevel,
						  enum conf_update_mode mode)
{
	int log_level;
	bool ok;

	ok = debug_level_parse(new_loglevel, &log_level);
	if (!ok) {
		D_ERR("Invalid value for [%s] -> %s = %s\n",
		      LEGACY_CONF_SECTION,
		      key,
		      new_loglevel);
		return false;
	}

	return true;
}

void legacy_conf_init(struct conf_context *conf)
{
	conf_define_section(conf, LEGACY_CONF_SECTION, NULL);

	conf_define_boolean(conf,
			    LEGACY_CONF_SECTION,
			    LEGACY_CONF_REALTIME_SCHEDULING,
			    true,
			    NULL);
	conf_define_boolean(conf,
			    LEGACY_CONF_SECTION,
			    LEGACY_CONF_RECMASTER_CAPABILITY,
			    true,
			    NULL);
	conf_define_boolean(conf,
			    LEGACY_CONF_SECTION,
			    LEGACY_CONF_LMASTER_CAPABILITY,
			    true,
			    NULL);
	conf_define_boolean(conf,
			    LEGACY_CONF_SECTION,
			    LEGACY_CONF_START_AS_STOPPED,
			    false,
			    NULL);
	conf_define_boolean(conf,
			    LEGACY_CONF_SECTION,
			    LEGACY_CONF_START_AS_DISABLED,
			    false,
			    NULL);
	conf_define_string(conf,
			   LEGACY_CONF_SECTION,
			   LEGACY_CONF_SCRIPT_LOG_LEVEL,
			   LEGACY_SCRIPT_LOG_LEVEL_DEFAULT,
			   legacy_conf_validate_script_log_level);
}
