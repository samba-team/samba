/*
   CTDB event daemon - config handling

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

#include <talloc.h>

#include "common/conf.h"
#include "common/logging_conf.h"
#include "common/path.h"

#include "event/event_private.h"
#include "event/event_conf.h"

struct event_config {
	char *config_file;
	struct conf_context *conf;

	const char *logging_location;
	const char *logging_loglevel;
	const char *debug_script;
};

int event_config_init(TALLOC_CTX *mem_ctx, struct event_config **result)
{
	struct event_config *config;
	int ret;
	bool ok;

	config = talloc_zero(mem_ctx, struct event_config);
	if (config == NULL) {
		return ENOMEM;
	}

	config->config_file = path_config(config);
	if (config->config_file == NULL) {
		talloc_free(config);
		return ENOMEM;
	}

	ret = conf_init(config, &config->conf);
	if (ret != 0) {
		talloc_free(config);
		return ret;
	}

	logging_conf_init(config->conf, NULL);

	conf_assign_string_pointer(config->conf,
				   LOGGING_CONF_SECTION,
				   LOGGING_CONF_LOCATION,
				   &config->logging_location);
	conf_assign_string_pointer(config->conf,
				   LOGGING_CONF_SECTION,
				   LOGGING_CONF_LOG_LEVEL,
				   &config->logging_loglevel);

	event_conf_init(config->conf);

	conf_assign_string_pointer(config->conf,
				   EVENT_CONF_SECTION,
				   EVENT_CONF_DEBUG_SCRIPT,
				   &config->debug_script);

	ok = conf_valid(config->conf);
	if (!ok) {
		talloc_free(config);
		return EINVAL;
	}

	ret = conf_load(config->conf, config->config_file, true);
	if (ret != 0 && ret != ENOENT) {
		talloc_free(config);
		return ret;
	}

	*result = config;
	return 0;
}

const char *event_config_log_location(struct event_config *config)
{
	return config->logging_location;
}

const char *event_config_log_level(struct event_config *config)
{
	return config->logging_loglevel;
}

const char *event_config_debug_script(struct event_config *config)
{
	return config->debug_script;
}

int event_config_reload(struct event_config *config)
{
	int ret;

	ret = conf_reload(config->conf);
	if (ret != 0 && ret != ENOENT) {
		return ret;
	}

	return 0;
}
