/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Support
 *  Copyright (C) Guenther Deschner 2007
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* FIXME: get rid of iniparser */
#include <iniparser.h>

struct gp_inifile_context {
	TALLOC_CTX *mem_ctx;
	dictionary *dict;
	const char *generated_filename;
};

/* prototypes */

NTSTATUS gp_inifile_init_context(TALLOC_CTX *mem_ctx, uint32_t flags,
				 const char *unix_path, const char *suffix,
				 struct gp_inifile_context **ctx_ret);
