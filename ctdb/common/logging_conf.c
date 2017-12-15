/*
   CTDB logging config handling

   Copyright (C) Martin Schwenke  2017

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

#include <talloc.h>

#include "common/conf.h"
#include "common/logging.h"
#include "common/logging_conf.h"

#define LOGGING_LOCATION_DEFAULT	"file:" LOGDIR "/log.ctdb"
#define LOGGING_LOG_LEVEL_DEFAULT	"ERROR"

static bool logging_conf_validate_log_level(const char *key,
					    const char *old_loglevel,
					    const char *new_loglevel,
					    enum conf_update_mode mode)
{
	int log_level;
	bool ok;

	ok = debug_level_parse(new_loglevel, &log_level);
	if (!ok) {
		return false;
	}

	return true;
}

static bool logging_conf_validate_location(const char *key,
					   const char *old_location,
					   const char *new_location,
					   enum conf_update_mode mode)
{
	bool ok;

	ok = logging_validate(new_location);
	if (!ok) {
		return false;
	}

	if (mode == CONF_MODE_RELOAD &&
	    strcmp(old_location, new_location) != 0) {
		D_WARNING("Ignoring update of %s config option \"%s\"\n",
			  LOGGING_CONF_SECTION, key);
		return false;
	}

	return true;
}

void logging_conf_init(struct conf_context *conf,
		       const char *default_log_level)
{
	const char *log_level;

	log_level = (default_log_level == NULL) ?
			LOGGING_LOG_LEVEL_DEFAULT :
			default_log_level;

	conf_define_section(conf, LOGGING_CONF_SECTION, NULL);

	conf_define_string(conf,
			   LOGGING_CONF_SECTION,
			   LOGGING_CONF_LOCATION,
			   LOGGING_LOCATION_DEFAULT,
			   logging_conf_validate_location);

	conf_define_string(conf,
			   LOGGING_CONF_SECTION,
			   LOGGING_CONF_LOG_LEVEL,
			   log_level,
			   logging_conf_validate_log_level);
}

const char *logging_conf_location(struct conf_context *conf)
{
	const char *out = NULL;
	int ret;

	ret = conf_get_string(conf,
			      LOGGING_CONF_SECTION,
			      LOGGING_CONF_LOCATION,
			      &out,
			      NULL);
	if (ret != 0) {
		/* Can't really happen, but return default */
		return LOGGING_LOCATION_DEFAULT;
	}

	return out;
}

const char *logging_conf_log_level(struct conf_context *conf)
{
	const char *out = NULL;
	int ret;

	ret = conf_get_string(conf,
			      LOGGING_CONF_SECTION,
			      LOGGING_CONF_LOG_LEVEL,
			      &out,
			      NULL);
	if (ret != 0) {
		/* Can't really happen, but return default */
		return LOGGING_LOG_LEVEL_DEFAULT;
	}

	return out;
}
