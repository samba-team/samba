/*
   Construct runtime paths

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

#ifndef __CTDB_PATH_H__
#define __CTDB_PATH_H__

#include <talloc.h>

const char *path_datadir(void);
const char *path_etcdir(void);
const char *path_rundir(void);
const char *path_vardir(void);

char *path_datadir_append(TALLOC_CTX *mem_ctx, const char *path);
char *path_etcdir_append(TALLOC_CTX *mem_ctx, const char *path);
char *path_rundir_append(TALLOC_CTX *mem_ctx, const char *path);
char *path_vardir_append(TALLOC_CTX *mem_ctx, const char *path);

char *path_config(TALLOC_CTX *mem_ctx);
char *path_socket(TALLOC_CTX *mem_ctx, const char *daemon);
char *path_pidfile(TALLOC_CTX *mem_ctx, const char *daemon);

#endif /* __CTDB_PATH_H__ */
