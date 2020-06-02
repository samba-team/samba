/*
 * Unix SMB/CIFS implementation.
 *
 * test suite for SMB2 replay
 *
 * Copyright (C) Anubhav Rakshit 2014
 * Copyright (C) Stefan Metzmacher 2014
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

#ifndef __OPLOCK_BREAK_HANDLER_H__
#define __OPLOCK_BREAK_HANDLER_H__

struct break_info {
	struct torture_context *tctx;
	bool oplock_skip_ack;
	struct smb2_handle handle;
	uint8_t level;
	struct smb2_break br;
	int count;
	int failures;
	NTSTATUS failure_status;
	struct smb2_transport *received_transport;
};

extern struct break_info break_info;

bool torture_oplock_ack_handler(struct smb2_transport *transport,
				const struct smb2_handle *handle,
				uint8_t level,
				void *private_data);
bool torture_oplock_ignore_handler(struct smb2_transport *transport,
				const struct smb2_handle *handle,
				uint8_t level,
				void *private_data);
void torture_wait_for_oplock_break(struct torture_context *tctx);

static inline void torture_reset_break_info(struct torture_context *tctx,
			      struct break_info *r)
{
	ZERO_STRUCTP(r);
	r->tctx = tctx;
}

#endif /* __OPLOCK_BREAK_HANDLER_H__ */
