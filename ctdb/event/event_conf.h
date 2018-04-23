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

#ifndef __CTDB_EVENT_CONF_H__
#define __CTDB_EVENT_CONF_H__

#include "common/conf.h"

#define EVENT_CONF_SECTION		"event"

#define EVENT_CONF_DEBUG_SCRIPT		"debug script"

void event_conf_init(struct conf_context *conf);

#endif /* __CTDB_EVENT_CONF_H__ */
