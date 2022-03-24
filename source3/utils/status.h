/*
 * Samba Unix/Linux SMB client library
 * State struct
 * Copyright (C) Jule Anger 2022
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"
#endif /* HAVE_JANSSON */

#ifndef STATUS_H
#define STATUS_H

struct traverse_state {
	bool json_output;
	bool first;
	bool resolve_uids;
#ifdef HAVE_JANSSON
	struct json_object root_json;
#endif /* HAVE_JANSSON */
};

enum crypto_degree {
        CRYPTO_DEGREE_NONE,
        CRYPTO_DEGREE_PARTIAL,
        CRYPTO_DEGREE_FULL
};

#endif
