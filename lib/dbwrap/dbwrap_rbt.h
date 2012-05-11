/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around red-black trees
   Copyright (C) Volker Lendecke 2007, 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __DBWRAP_RBT_H__
#define __DBWRAP_RBT_H__

#include <talloc.h>

struct db_context;

struct db_context *db_open_rbt(TALLOC_CTX *mem_ctx);

#endif /* __DBWRAP_RBT_H__ */
