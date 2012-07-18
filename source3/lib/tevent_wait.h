/*
   Unix SMB/CIFS implementation.
   Implement a send/recv interface to wait for an external trigger
   Copyright (C) Volker Lendecke 2012

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

#ifndef _TEVENT_WAIT_H
#define _TEVENT_WAIT_H

#include "talloc.h"
#include "tevent.h"

/*
 * Just wait for getting a tevent_wait_done. tevent_wait_done can deal with a
 * NULL request.
 */

struct tevent_req *tevent_wait_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev);
int tevent_wait_recv(struct tevent_req *req);

void tevent_wait_done(struct tevent_req *req);

#endif /* _TEVENT_WAIT_H */
