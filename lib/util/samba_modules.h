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

#ifndef _SAMBA_MODULES_H
#define _SAMBA_MODULES_H

/* Module support */
typedef NTSTATUS (*init_module_fn) (TALLOC_CTX *ctx);

NTSTATUS samba_init_module(TALLOC_CTX *ctx);

/* this needs to be a string which is not in the C library. We
   previously used "init_module", but that meant that modules which
   did not define this function ended up calling the C library
   function init_module() which makes a system call */
#define SAMBA_INIT_MODULE "samba_init_module"

/**
 * Obtain the init function from a shared library file.  
 *
 * The handle to dlclose() in case of error is returns in *handle if handle is not NULL
 */
init_module_fn load_module(const char *path, bool is_probe, void **handle);

/**
 * Run the specified init functions.
 *
 * @return true if all functions ran successfully, false otherwise
 */
bool run_init_functions(TALLOC_CTX *ctx, init_module_fn *fns);

/**
 * Load the initialization functions from DSO files for a specific subsystem.
 *
 * Will return an array of function pointers to initialization functions
 */
init_module_fn *load_samba_modules(TALLOC_CTX *mem_ctx, const char *subsystem);

int smb_load_all_modules_absoute_path(const char **modules);
NTSTATUS smb_probe_module(const char *subsystem, const char *module);
NTSTATUS smb_probe_module_absolute_path(const char *module);
NTSTATUS smb_load_module(const char *subsystem, const char *module);

#endif /* _SAMBA_MODULES_H */
