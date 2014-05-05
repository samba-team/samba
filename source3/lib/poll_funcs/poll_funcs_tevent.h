/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013,2014
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

#ifndef __POLL_FUNCS_TEVENT_H__
#define __POLL_FUNCS_TEVENT_H__

#include "poll_funcs.h"
#include "tevent.h"

/*
 * Create a new, empty instance of "struct poll_funcs" to be served by tevent.
 */
struct poll_funcs *poll_funcs_init_tevent(TALLOC_CTX *mem_ctx);

/*
 * Register a tevent_context to handle the watches that the user of
 * "poll_funcs" showed interest in. talloc_free() the returned pointer when
 * "ev" is not supposed to handle the events anymore.
 */
void *poll_funcs_tevent_register(TALLOC_CTX *mem_ctx, struct poll_funcs *f,
				 struct tevent_context *ev);

#endif
