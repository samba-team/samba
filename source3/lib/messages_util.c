/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2013 by Volker Lendecke
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

#include "replace.h"
#include "lib/util/server_id.h"
#include "lib/util/samba_util.h"
#include "librpc/gen_ndr/server_id.h"
#include "lib/util/byteorder.h"
#include "messages_util.h"

void message_hdr_put(uint8_t buf[MESSAGE_HDR_LENGTH], uint32_t msg_type,
		     struct server_id src, struct server_id dst)
{
	server_id_put(buf, dst);
	server_id_put(buf + SERVER_ID_BUF_LENGTH, src);
	SIVAL(buf, 2 * SERVER_ID_BUF_LENGTH, msg_type);
}

void message_hdr_get(uint32_t *msg_type, struct server_id *src,
		     struct server_id *dst,
		     const uint8_t buf[MESSAGE_HDR_LENGTH])
{
	server_id_get(dst, buf);
	server_id_get(src, buf + SERVER_ID_BUF_LENGTH);
	*msg_type = IVAL(buf, 2 * SERVER_ID_BUF_LENGTH);
}
