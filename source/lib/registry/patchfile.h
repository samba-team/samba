/* 
   Unix SMB/CIFS implementation.
   Patchfile interface
   Copyright (C) Jelmer Vernooij 2006
   Copyright (C) Wilco Baan Hofman 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _PATCHFILE_H
#define _PATCHFILE_H 

#include "lib/registry/registry.h"

struct reg_diff_callbacks {
	WERROR (*add_key) (void *callback_data, const char *key_name);
	WERROR (*set_value) (void *callback_data, const char *key_name, 
						 const char *value_name, uint32_t value_type, DATA_BLOB value);
	WERROR (*del_value) (void *callback_data, const char *key_name, const char *value_name);
	WERROR (*del_key) (void *callback_data, const char *key_name);
	WERROR (*del_all_values) (void *callback_data, const char *key_name);
	WERROR (*done) (void *callback_data);
};

WERROR reg_diff_apply (const char *filename, 
								struct registry_context *ctx);

WERROR reg_generate_diff(struct registry_context *ctx1, 
				  struct registry_context *ctx2, 
				  const struct reg_diff_callbacks *callbacks,
				  void *callback_data);
WERROR reg_dotreg_diff_save(TALLOC_CTX *ctx, const char *filename, 
				struct reg_diff_callbacks **callbacks, void **callback_data);
WERROR reg_generate_diff_key(struct registry_key *oldkey, 
				    struct registry_key *newkey,
				    const char *path,
				    const struct reg_diff_callbacks *callbacks,
				    void *callback_data);

#endif /* _PATCHFILE_H */
