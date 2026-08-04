/*
   Unix SMB/CIFS implementation.
   Wrap HRESULT errors around tevent_req
   Copyright (C) Ralph Boehme 2026

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

#include "lib/replace/replace.h"
#include "tevent_hresult.h"
#include "libcli/util/error.h"
#include "libcli/util/ntstatus_gen.h"

#define TEVENT_HERROR_MAGIC (UINT64_C(0x917b5ace) << 32)
#define TEVENT_HERROR_MAGIC_MASK (UINT64_C(0xffffffff) << 32)

bool _tevent_req_herror(struct tevent_req *req,
			HRESULT hres,
			const char *location)
{
	uint64_t err;

	if (HRES_IS_OK(hres)) {
		return false;
	}

	err = TEVENT_HERROR_MAGIC | HRES_ERROR_V(hres);

	return _tevent_req_error(req, err, location);
}

bool tevent_req_is_herror(struct tevent_req *req, HRESULT *hres)
{
	enum tevent_req_state state;
	uint64_t err;

	if (!tevent_req_is_error(req, &state, &err)) {
		return false;
	}
	switch (state) {
	case TEVENT_REQ_TIMED_OUT:
		*hres = HRES_RPC_E_TIMEOUT;
		break;
	case TEVENT_REQ_NO_MEMORY:
		*hres = HRES_E_OUTOFMEMORY;
		break;
	case TEVENT_REQ_USER_ERROR:
		if ((err & TEVENT_HERROR_MAGIC_MASK) != TEVENT_HERROR_MAGIC) {
			abort();
		}
		*hres = HRES_ERROR(err & ~(TEVENT_HERROR_MAGIC_MASK));
		break;
	default:
		*hres = HRES_E_FAIL;
		break;
	}
	return true;
}

HRESULT tevent_req_simple_recv_hresult(struct tevent_req *req)
{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	tevent_req_received(req);
	return HRES_ERROR(0);
}
