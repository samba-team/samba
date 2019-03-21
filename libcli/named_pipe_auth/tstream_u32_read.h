/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2019
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

#ifndef TSTREAM_U32_READ_H
#define TSTREAM_U32_READ_H

#include "replace.h"
#include "tsocket.h"

struct tevent_req *tstream_u32_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t max_msglen,
	struct tstream_context *stream);
int tstream_u32_read_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	uint8_t **buf,
	size_t *buflen);

#endif
