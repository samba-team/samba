/*
   Unix SMB/CIFS implementation.

   file_id structure handling

   Copyright (C) Andrew Tridgell 2007

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

#include "librpc/gen_ndr/file_id.h"

/* The following definitions come from lib/file_id.c  */

bool file_id_equal(const struct file_id *id1, const struct file_id *id2);
/*
  a static-like (on talloc_tos()) string for a file_id structure
 */
const char *file_id_string_tos(const struct file_id *id);
/*
  an allocated string for a file_id structure
 */
const char *file_id_string(TALLOC_CTX *mem_ctx, const struct file_id *id);
void push_file_id_16(char *buf, const struct file_id *id);
void push_file_id_24(char *buf, const struct file_id *id);
void pull_file_id_24(const char *buf, struct file_id *id);
