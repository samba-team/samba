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

#ifndef TEVENT_HRESULT_H
#define TEVENT_HRESULT_H

#include <stdint.h>
#include <stdbool.h>
#include <tevent.h>
#include "libcli/util/ntstatus.h"
#include "libcli/util/hresult.h"

bool _tevent_req_herror(struct tevent_req *req,
			HRESULT hres,
			const char *location);
#define tevent_req_herror(req, hres) \
	_tevent_req_herror(req, hres, __location__)

bool tevent_req_is_herror(struct tevent_req *req, HRESULT *hres);
HRESULT tevent_req_simple_recv_hresult(struct tevent_req *req);
#endif
