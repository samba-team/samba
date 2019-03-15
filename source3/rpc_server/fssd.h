/*
 *  Unix SMB/CIFS implementation.
 *
 *  FSSD header file
 *
 *  Copyright (c) 2018 Volker Lendecke <vl@samba.org>
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

#ifndef __RPC_SERVER_FSSD_H__
#define __RPC_SERVER_FSSD_H__

#include "replace.h"
#include "messages.h"

void start_fssd(struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx);

#endif
