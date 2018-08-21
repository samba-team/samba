/*
   CTDB database config handling

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

#include "failover/failover_conf.h"

static bool check_static_boolean_change(const char *key,
					bool old_value,
					bool new_value,
					enum conf_update_mode mode)
{
	if (mode == CONF_MODE_RELOAD || CONF_MODE_API) {
		if (old_value != new_value) {
			D_WARNING("Ignoring update of [%s] -> %s\n",
				  FAILOVER_CONF_SECTION,
				  key);
		}
	}

	return true;
}

void failover_conf_init(struct conf_context *conf)
{
	conf_define_section(conf, FAILOVER_CONF_SECTION, NULL);

	conf_define_boolean(conf,
			    FAILOVER_CONF_SECTION,
			    FAILOVER_CONF_DISABLED,
			    false,
			    check_static_boolean_change);
}
