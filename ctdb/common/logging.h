/*
   Logging utilities

   Copyright (C) Amitay Isaacs  2015

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

#ifndef __CTDB_LOGGING_H__
#define __CTDB_LOGGING_H__

#include <talloc.h>
#include "lib/util/debug.h"

#define DEBUG_ERR     DBGLVL_ERR
#define DEBUG_WARNING DBGLVL_WARNING
#define DEBUG_NOTICE  DBGLVL_NOTICE
#define DEBUG_INFO    DBGLVL_INFO
#define DEBUG_DEBUG   DBGLVL_DEBUG

/* These are used in many places, so define them here to avoid churn */
#define DEBUG_ALERT DEBUG_ERR
#define	DEBUG_CRIT  DEBUG_ERR

bool debug_level_parse(const char *log_string, int *log_level);
const char *debug_level_to_string(int log_level);
int debug_level_from_string(const char *log_string);

bool logging_validate(const char *logging);
int logging_init(TALLOC_CTX *mem_ctx, const char *logging,
		 const char *debuglevel, const char *app_name);

#endif /* __CTDB_LOGGING_H__ */
