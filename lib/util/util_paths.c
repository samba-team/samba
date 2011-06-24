/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006

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

#include "includes.h"
#include "dynconfig/dynconfig.h"

/**
 * @brief Returns an absolute path to a file in the Samba modules directory.
 *
 * @param name File to find, relative to MODULESDIR.
 *
 * @retval Pointer to a string containing the full path.
 **/

char *modules_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s", get_dyn_MODULESDIR(), name);
}

/**
 * @brief Returns an absolute path to a file in the Samba data directory.
 *
 * @param name File to find, relative to CODEPAGEDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *data_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s", get_dyn_CODEPAGEDIR(), name);
}

/**
 * @brief Returns the platform specific shared library extension.
 *
 * @retval Pointer to a const char * containing the extension.
 **/

const char *shlib_ext(void)
{
	return get_dyn_SHLIBEXT();
}

