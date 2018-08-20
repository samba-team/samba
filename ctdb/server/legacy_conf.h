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

#ifndef __CTDB_LEGACY_CONF_H__
#define __CTDB_LEGACY_CONF_H__

#include "common/conf.h"

#define LEGACY_CONF_SECTION "legacy"

#define LEGACY_CONF_REALTIME_SCHEDULING  "realtime scheduling"
#define LEGACY_CONF_RECMASTER_CAPABILITY "recmaster capability"
#define LEGACY_CONF_LMASTER_CAPABILITY   "lmaster capability"
#define LEGACY_CONF_START_AS_STOPPED     "start as stopped"
#define LEGACY_CONF_START_AS_DISABLED    "start as disabled"
#define LEGACY_CONF_SCRIPT_LOG_LEVEL     "script log level"

void legacy_conf_init(struct conf_context *conf);

#endif /* __CTDB_LEGACY_CONF_H__ */
