/* 
 *  Unix SMB/CIFS implementation.
 *
 *  RPC Pipe client / server routines
 *
 *  Copyright (C) Volker Lendecke 2005
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

void init_q_unixinfo_sid_to_uid(UNIXINFO_Q_SID_TO_UID *q_d, const DOM_SID *sid)
{
	sid_copy(&q_d->sid, sid);
}

BOOL unixinfo_io_q_unixinfo_sid_to_uid(const char *desc, UNIXINFO_Q_SID_TO_UID *q_d,
				 prs_struct *ps, int depth)
{
	return smb_io_dom_sid(desc, &q_d->sid, ps, depth);
}

BOOL unixinfo_io_r_unixinfo_sid_to_uid(const char *desc, UNIXINFO_R_SID_TO_UID *r_d,
				 prs_struct *ps, int depth)
{
	if (!prs_uint64(desc, ps, depth, &r_d->uid))
		return False;

	if (!prs_ntstatus(desc, ps, depth, &r_d->status))
		return False;

	return True;
}

void init_q_unixinfo_uid_to_sid(UNIXINFO_Q_UID_TO_SID *q_d, uint64 uid)
{
	q_d->uid = uid;
}

BOOL unixinfo_io_q_unixinfo_uid_to_sid(const char *desc, UNIXINFO_Q_UID_TO_SID *q_d,
				 prs_struct *ps, int depth)
{
	return prs_uint64(desc, ps, depth, &q_d->uid);
}

void init_r_unixinfo_uid_to_sid(UNIXINFO_R_UID_TO_SID *r_d, DOM_SID *sid)
{
	if (sid == NULL) {
		r_d->sidptr = 0;
		return;
	}
	r_d->sidptr = 1;
	sid_copy(&r_d->sid, sid);
}

BOOL unixinfo_io_r_unixinfo_uid_to_sid(const char *desc, UNIXINFO_R_UID_TO_SID *r_d,
				 prs_struct *ps, int depth)
{
	if (!prs_uint32("sidptr", ps, depth, &r_d->sidptr))
		return False;

	if (r_d->sidptr != 0) {
		if (!smb_io_dom_sid(desc, &r_d->sid, ps, depth))
			return False;
	}

	if (!prs_ntstatus(desc, ps, depth, &r_d->status))
		return False;

	return True;
}

void init_q_unixinfo_sid_to_gid(UNIXINFO_Q_SID_TO_GID *q_d, const DOM_SID *sid)
{
	sid_copy(&q_d->sid, sid);
}

BOOL unixinfo_io_q_unixinfo_sid_to_gid(const char *desc, UNIXINFO_Q_SID_TO_GID *q_d,
				 prs_struct *ps, int depth)
{
	return smb_io_dom_sid(desc, &q_d->sid, ps, depth);
}

void init_r_unixinfo_sid_to_gid(UNIXINFO_R_SID_TO_GID *r_d, uint64 gid)
{
	r_d->gid = gid;
	r_d->status = NT_STATUS_OK;
}

BOOL unixinfo_io_r_unixinfo_sid_to_gid(const char *desc, UNIXINFO_R_SID_TO_GID *r_d,
				 prs_struct *ps, int depth)
{
	if (!prs_uint64(desc, ps, depth, &r_d->gid))
		return False;

	if (!prs_ntstatus(desc, ps, depth, &r_d->status))
		return False;

	return True;
}

void init_q_unixinfo_gid_to_sid(UNIXINFO_Q_GID_TO_SID *q_d, uint64 gid)
{
	q_d->gid = gid;
}

BOOL unixinfo_io_q_unixinfo_gid_to_sid(const char *desc, UNIXINFO_Q_GID_TO_SID *q_d,
				 prs_struct *ps, int depth)
{
	return prs_uint64(desc, ps, depth, &q_d->gid);
}

void init_r_unixinfo_gid_to_sid(UNIXINFO_R_GID_TO_SID *r_d, DOM_SID *sid)
{
	if (sid == NULL) {
		r_d->sidptr = 0;
		return;
	}
	r_d->sidptr = 1;
	sid_copy(&r_d->sid, sid);
}

BOOL unixinfo_io_r_unixinfo_gid_to_sid(const char *desc, UNIXINFO_R_GID_TO_SID *r_d,
				 prs_struct *ps, int depth)
{
	if (!prs_uint32("sidptr", ps, depth, &r_d->sidptr))
		return False;

	if (r_d->sidptr != 0) {
		if (!smb_io_dom_sid(desc, &r_d->sid, ps, depth))
			return False;
	}

	if (!prs_ntstatus(desc, ps, depth, &r_d->status))
		return False;

	return True;
}

void init_q_unixinfo_getpwuid(UNIXINFO_Q_GETPWUID *r_d, int count,
			      uint64 *uids)
{
	r_d->count = count;
	r_d->uid = uids;
}

BOOL unixinfo_io_q_unixinfo_getpwuid(const char *desc,
				     UNIXINFO_Q_GETPWUID *q_d,
				     prs_struct *ps, int depth)
{
	uint32 arraysize;
	int i;

	if (!prs_uint32("count", ps, depth, &q_d->count))
		return False;

	arraysize = q_d->count;

	if (!prs_uint32("arraysize", ps, depth, &arraysize))
		return False;

	if (arraysize != q_d->count) {
		DEBUG(10, ("count!=arraysize\n"));
		return False;
	}

	if (q_d->count > 1023) {
		DEBUG(10, ("Range exceeded\n"));
		return False;
	}

	if (UNMARSHALLING(ps)) {
		q_d->uid = PRS_ALLOC_MEM(ps, uint64, q_d->count);
		if (q_d->uid == NULL) {
			return False;
		}
	}

	for (i=0; i<q_d->count; i++) {
		if (!prs_uint64(desc, ps, depth+1, &q_d->uid[i]))
			return False;
	}

	return True;
}

void init_r_unixinfo_getpwuid(UNIXINFO_R_GETPWUID *r_d, uint32 count,
			      struct unixinfo_getpwuid *info)
{
	r_d->count = count;
	r_d->info = info;
}

BOOL unixinfo_io_r_unixinfo_getpwuid(const char *desc,
				     UNIXINFO_R_GETPWUID *r_d,
				     prs_struct *ps, int depth)
{
	uint32 arraysize;
	int i;

	if (!prs_uint32("count", ps, depth, &r_d->count))
		return False;

	arraysize = r_d->count;

	if (!prs_uint32("arraysize", ps, depth, &arraysize))
		return False;

	if (arraysize != r_d->count) {
		DEBUG(10, ("count!=arraysize\n"));
		return False;
	}

	if (r_d->count > 1023) {
		DEBUG(10, ("Range exceeded\n"));
		return False;
	}

	if (UNMARSHALLING(ps)) {
		r_d->info = PRS_ALLOC_MEM(ps, struct unixinfo_getpwuid,
					  r_d->count);
		if (r_d->info == NULL) {
			return False;
		}
	}

	for (i=0; i<r_d->count; i++) {
		if (!prs_align(ps))
			return False;

		if (!prs_ntstatus("status", ps, depth+1, &r_d->info[i].status))
			return False;

		if (!prs_string_alloc("homedir", ps, depth+1,
				      &r_d->info[i].homedir))
			return False;

		if (!prs_string_alloc("shell", ps, depth+1,
				      &r_d->info[i].shell))
			return False;
	}

	if (!prs_align(ps))
		return False;

	if (!prs_ntstatus(desc, ps, depth, &r_d->status))
		return False;

	return True;
}
