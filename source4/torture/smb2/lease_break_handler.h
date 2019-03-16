/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 leases

   Copyright (C) Zachary Loafman 2009

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

#include "torture/util.h"

struct lease_break_info {
	struct torture_context *tctx;

	struct smb2_lease_break lease_break;
	struct smb2_transport *lease_transport;
	bool lease_skip_ack;
	struct smb2_lease_break_ack lease_break_ack;
	int count;
	int failures;

	struct smb2_handle oplock_handle;
	uint8_t held_oplock_level;
	uint8_t oplock_level;
	int oplock_count;
	int oplock_failures;
};

#define CHECK_LEASE_BREAK(__lb, __oldstate, __state, __key)		\
	do {								\
		uint16_t __new = smb2_util_lease_state(__state); \
		uint16_t __old = smb2_util_lease_state(__oldstate); \
		CHECK_VAL((__lb)->new_lease_state, __new);	\
		CHECK_VAL((__lb)->current_lease.lease_state, __old); \
		CHECK_VAL((__lb)->current_lease.lease_key.data[0], (__key)); \
		CHECK_VAL((__lb)->current_lease.lease_key.data[1], ~(__key)); \
		if (__old & (SMB2_LEASE_WRITE | SMB2_LEASE_HANDLE)) { \
			CHECK_VAL((__lb)->break_flags, \
				  SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED);	\
		} else { \
			CHECK_VAL((__lb)->break_flags, 0); \
		} \
	} while(0)

#define CHECK_LEASE_BREAK_ACK(__lba, __state, __key)			\
	do {								\
		CHECK_VAL((__lba)->out.reserved, 0);			\
		CHECK_VAL((__lba)->out.lease.lease_key.data[0], (__key)); \
		CHECK_VAL((__lba)->out.lease.lease_key.data[1], ~(__key)); \
		CHECK_VAL((__lba)->out.lease.lease_state, smb2_util_lease_state(__state)); \
		CHECK_VAL((__lba)->out.lease.lease_flags, 0);		\
		CHECK_VAL((__lba)->out.lease.lease_duration, 0);	\
	} while(0)

#define CHECK_NO_BREAK(tctx)	\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(lease_break_info.failures, 0);			\
		CHECK_VAL(lease_break_info.count, 0);				\
		CHECK_VAL(lease_break_info.oplock_failures, 0);		\
		CHECK_VAL(lease_break_info.oplock_count, 0);			\
	} while(0)

#define CHECK_OPLOCK_BREAK(__brokento)	\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(lease_break_info.oplock_count, 1);			\
		CHECK_VAL(lease_break_info.oplock_failures, 0);		\
		CHECK_VAL(lease_break_info.oplock_level,			\
			  smb2_util_oplock_level(__brokento)); \
		lease_break_info.held_oplock_level = lease_break_info.oplock_level; \
	} while(0)

#define _CHECK_BREAK_INFO(__oldstate, __state, __key)			\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(lease_break_info.failures, 0);			\
		CHECK_VAL(lease_break_info.count, 1);				\
		CHECK_LEASE_BREAK(&lease_break_info.lease_break, (__oldstate), \
		    (__state), (__key));				\
		if (!lease_break_info.lease_skip_ack && \
		    (lease_break_info.lease_break.break_flags &		\
		     SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED))	\
		{	\
			torture_wait_for_lease_break(tctx);		\
			CHECK_LEASE_BREAK_ACK(&lease_break_info.lease_break_ack, \
				              (__state), (__key));	\
		}							\
	} while(0)

#define CHECK_BREAK_INFO(__oldstate, __state, __key)			\
	do {								\
		_CHECK_BREAK_INFO(__oldstate, __state, __key);		\
		CHECK_VAL(lease_break_info.lease_break.new_epoch, 0);		\
	} while(0)

#define CHECK_BREAK_INFO_V2(__transport, __oldstate, __state, __key, __epoch) \
	do {								\
		_CHECK_BREAK_INFO(__oldstate, __state, __key);		\
		CHECK_VAL(lease_break_info.lease_break.new_epoch, __epoch);	\
		if (!TARGET_IS_SAMBA3(tctx)) {				\
			CHECK_VAL((uintptr_t)lease_break_info.lease_transport, \
				  (uintptr_t)__transport);		\
		} \
	} while(0)

extern struct lease_break_info lease_break_info;

bool torture_lease_handler(struct smb2_transport *transport,
			   const struct smb2_lease_break *lb,
			   void *private_data);
bool torture_lease_ignore_handler(struct smb2_transport *transport,
				  const struct smb2_lease_break *lb,
				  void *private_data);
void torture_wait_for_lease_break(struct torture_context *tctx);

static inline void torture_reset_lease_break_info(struct torture_context *tctx,
						  struct lease_break_info *r)
{
	ZERO_STRUCTP(r);
	r->tctx = tctx;
}
