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

#ifndef __LOGGING_CONF_H__
#define __LOGGING_CONF_H__

#include "common/conf.h"

#define LOGGING_CONF_SECTION	"logging"

#define LOGGING_CONF_LOCATION	"location"
#define LOGGING_CONF_LOG_LEVEL	"log level"

void logging_conf_init(struct conf_context *conf,
		       const char *default_log_level);

const char *logging_conf_location(struct conf_context *conf);
const char *logging_conf_log_level(struct conf_context *conf);

#endif /* __LOGGING_CONF_H__ */
