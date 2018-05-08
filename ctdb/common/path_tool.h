/*
   path tool

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

#ifndef __CTDB_PATH_TOOL__
#define __CTDB_PATH_TOOL__

#include <talloc.h>
#include <popt.h>

struct path_tool_context;

int path_tool_init(TALLOC_CTX *mem_ctx,
		   const char *prog,
		   struct poptOption *options,
		   int argc,
		   const char **argv,
		   bool parse_options,
		   struct path_tool_context **result);

int path_tool_run(struct path_tool_context *ctx, int *result);

#endif /* __CTDB_PATH_TOOL__ */
