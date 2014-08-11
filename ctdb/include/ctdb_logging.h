/*
   ctdb logging code

   Copyright (C) Andrew Tridgell  2008

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

#ifndef _CTDB_LOGGING_H_
#define _CTDB_LOGGING_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <talloc.h>

extern const char *debug_extra;

enum debug_level {
	DEBUG_ERR     =  0,
	DEBUG_WARNING =  1,
	DEBUG_NOTICE  =  2,
	DEBUG_INFO    =  3,
	DEBUG_DEBUG   =  4,
};

/* These are used in many places, so define them here to avoid churn */
#define DEBUG_ALERT DEBUG_ERR
#define	DEBUG_CRIT  DEBUG_ERR

const char *get_debug_by_level(int32_t level);
bool parse_debug(const char *str, int32_t *level);
void print_debug_levels(FILE *stream);

bool ctdb_logging_init(TALLOC_CTX *mem_ctx, const char *logging);
typedef int (*ctdb_log_setup_fn_t)(TALLOC_CTX *mem_ctx,
				   const char *logging,
				   const char *app_name);
void ctdb_log_register_backend(const char *prefix, ctdb_log_setup_fn_t init);
void ctdb_log_init_file(void);
void ctdb_log_init_syslog(void);

#endif /* _CTDB_LOGGING_H_ */
