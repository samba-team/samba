/*
   Unix SMB/CIFS implementation.

   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2023

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SOURCE3_WINBIND_VARLINK_H_
#define _SOURCE3_WINBIND_VARLINK_H_

#include <talloc.h>
#include <tevent.h>
#include <varlink.h>

#define WB_VL_SERVICE_NAME "org.samba.winbind"

#define WB_VL_REPLY_ERROR_NO_RECORD_FOUND \
	"io.systemd.UserDatabase.NoRecordFound"
#define WB_VL_REPLY_ERROR_BAD_SERVICE \
	"io.systemd.UserDatabase.BadService"
#define WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE \
	"io.systemd.UserDatabase.ServiceNotAvailable"
#define WB_VL_REPLY_ERROR_CONFLICTING_RECORD_FOUND \
	"io.systemd.UserDatabase.ConflictingRecordFound"
#define WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED \
	"io.systemd.UserDatabase.EnumerationNotSupported"

NTSTATUS wb_vl_fake_cli_state(VarlinkCall *call,
			      const char *service,
			      struct winbindd_cli_state *cli);

/* GetUserRecord */
NTSTATUS wb_vl_user_enumerate(TALLOC_CTX *state,
			      struct tevent_context *ev_ctx,
			      VarlinkCall *call,
			      uint64_t flags,
			      const char *service);

bool winbind_setup_varlink(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx);

#endif /* _SOURCE3_WINBIND_VARLINK_H_ */
