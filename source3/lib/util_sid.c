/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 		1992-1998
   Copyright (C) Luke Kenneth Caseson Leighton 	1998-1999
   Copyright (C) Jeremy Allison  		1999
   Copyright (C) Stefan (metze) Metzmacher 	2002
   Copyright (C) Simo Sorce 			2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005

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

#include "includes.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"


/*****************************************************************
 Convert a SID to an ascii string.
*****************************************************************/

char *sid_to_fstring(fstring sidstr_out, const struct dom_sid *sid)
{
	struct dom_sid_buf buf;
	fstrcpy(sidstr_out, dom_sid_str_buf(sid, &buf));
	return sidstr_out;
}

/*****************************************************************
 Write a sid out into on-the-wire format.
*****************************************************************/  

bool sid_linearize(uint8_t *outbuf, size_t len, const struct dom_sid *sid)
{
	int8_t i;

	if (len < ndr_size_dom_sid(sid, 0))
		return False;

	SCVAL(outbuf,0,sid->sid_rev_num);
	SCVAL(outbuf,1,sid->num_auths);
	memcpy(&outbuf[2], sid->id_auth, 6);
	for(i = 0; i < sid->num_auths; i++)
		SIVAL(outbuf, 8 + (i*4), sid->sub_auths[i]);

	return True;
}

/*****************************************************************
 Returns true if SID is internal (and non-mappable).
*****************************************************************/

bool non_mappable_sid(struct dom_sid *sid)
{
	struct dom_sid dom;

	sid_copy(&dom, sid);
	sid_split_rid(&dom, NULL);

	if (dom_sid_equal(&dom, &global_sid_Builtin))
		return True;

	if (dom_sid_equal(&dom, &global_sid_NT_Authority))
		return True;

	return False;
}

/*****************************************************************
 Return the binary string representation of a struct dom_sid.
 Caller must free.
*****************************************************************/

char *sid_binstring_hex_talloc(TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	int len = ndr_size_dom_sid(sid, 0);
	uint8_t buf[len];
	sid_linearize(buf, len, sid);
	return hex_encode_talloc(mem_ctx, buf, len);
}

NTSTATUS sid_array_from_info3(TALLOC_CTX *mem_ctx,
			      const struct netr_SamInfo3 *info3,
			      struct dom_sid **user_sids,
			      uint32_t *num_user_sids,
			      bool include_user_group_rid)
{
	NTSTATUS status;
	struct dom_sid sid;
	struct dom_sid *sid_array = NULL;
	uint32_t num_sids = 0;
	uint32_t i;

	if (include_user_group_rid) {
		if (!sid_compose(&sid, info3->base.domain_sid, info3->base.rid)) {
			DEBUG(3, ("could not compose user SID from rid 0x%x\n",
				  info3->base.rid));
			return NT_STATUS_INVALID_PARAMETER;
		}
		status = add_sid_to_array(mem_ctx, &sid, &sid_array, &num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("could not append user SID from rid 0x%x\n",
				  info3->base.rid));
			return status;
		}
	}

	if (!sid_compose(&sid, info3->base.domain_sid, info3->base.primary_gid)) {
		DEBUG(3, ("could not compose group SID from rid 0x%x\n",
			  info3->base.primary_gid));
		return NT_STATUS_INVALID_PARAMETER;
	}
	status = add_sid_to_array(mem_ctx, &sid, &sid_array, &num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not append group SID from rid 0x%x\n",
			  info3->base.rid));
		return status;
	}

	for (i = 0; i < info3->base.groups.count; i++) {
		/* Don't add the primary group sid twice. */
		if (info3->base.primary_gid == info3->base.groups.rids[i].rid) {
			continue;
		}
		if (!sid_compose(&sid, info3->base.domain_sid,
				 info3->base.groups.rids[i].rid)) {
			DEBUG(3, ("could not compose SID from additional group "
				  "rid 0x%x\n", info3->base.groups.rids[i].rid));
			return NT_STATUS_INVALID_PARAMETER;
		}
		status = add_sid_to_array(mem_ctx, &sid, &sid_array, &num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("could not append SID from additional group "
				  "rid 0x%x\n", info3->base.groups.rids[i].rid));
			return status;
		}
	}

	/* Copy 'other' sids.  We need to do sid filtering here to
 	   prevent possible elevation of privileges.  See:

           http://www.microsoft.com/windows2000/techinfo/administration/security/sidfilter.asp
         */

	for (i = 0; i < info3->sidcount; i++) {

		if (sid_check_is_in_asserted_identity(info3->sids[i].sid)) {
			continue;
		}

		status = add_sid_to_array(mem_ctx, info3->sids[i].sid,
				      &sid_array, &num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			struct dom_sid_buf buf;
			DEBUG(3, ("could not add SID to array: %s\n",
				  dom_sid_str_buf(info3->sids[i].sid, &buf)));
			return status;
		}
	}

	*user_sids = sid_array;
	*num_user_sids = num_sids;

	return NT_STATUS_OK;
}
