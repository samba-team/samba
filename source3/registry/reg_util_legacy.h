/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2009
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

#ifndef _REG_UTIL_LEGACY_H
#define _REG_UTIL_LEGACY_H

/*
 * This module contains legacy code code from the old regkey
 * interface that is now mostly hidden behind the reg_api interface.
 * This code should be removed once the last users of the old code
 * have been converted.
 */

#include "includes.h"
#include "registry.h"

/**
 * legacy open key function that should be replaced by uses of
 * reg_open_path
 */

WERROR regkey_open_internal(TALLOC_CTX *ctx,
			    struct registry_key_handle **regkey,
			    const char *path,
			    const struct nt_user_token *token,
			    uint32 access_desired );

#endif /* _REG_UTIL_LEGACY_H */
