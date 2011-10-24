/*
   Unix SMB/CIFS implementation.
   Handling of idle/exit events
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Andrew Bartlett 2011

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

#ifndef _INTERNAL_MODULES_H
#define _INTERNAL_MODULES_H

#include "lib/util/samba_module.h"

/**
 * Obtain the init function from a shared library file.
 *
 * The handle to dlclose() in case of error is returns in *handle if handle is not NULL
 */
samba_init_module_fn load_module(const char *path, bool is_probe, void **handle);

int smb_load_modules(const char **modules);
NTSTATUS smb_probe_module(const char *subsystem, const char *module);

/**
 * Obtain list of init functions from the modules in the specified
 * directory
 */
samba_init_module_fn *load_modules(TALLOC_CTX *mem_ctx, const char *path);

#endif /* _INTERNAL_MODULES_H */
