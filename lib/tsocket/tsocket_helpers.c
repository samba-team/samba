/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "tsocket.h"
#include "tsocket_internal.h"

int tsocket_simple_int_recv(struct tevent_req *req, int *perrno)
{
	enum tevent_req_state state;
	uint64_t error;

	if (!tevent_req_is_error(req, &state, &error)) {
		return 0;
	}

	switch (state) {
	case TEVENT_REQ_NO_MEMORY:
		*perrno = ENOMEM;
		return -1;
	case TEVENT_REQ_TIMED_OUT:
		*perrno = ETIMEDOUT;
		return -1;
	case TEVENT_REQ_USER_ERROR:
		*perrno = (int)error;
		return -1;
	default:
		*perrno = EIO;
		return -1;
	}

	*perrno = EIO;
	return -1;
}
