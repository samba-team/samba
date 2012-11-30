/* 
   Unix SMB/CIFS implementation.
   client security descriptor functions
   Copyright (C) Andrew Tridgell 2000

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
#include "libsmb/libsmb.h"
#include "../libcli/security/secdesc.h"

NTSTATUS cli_query_security_descriptor(struct cli_state *cli,
				       uint16_t fnum,
				       uint32_t sec_info,
				       TALLOC_CTX *mem_ctx,
				       struct security_descriptor **sd)
{
	uint8_t param[8];
	uint8_t *rdata=NULL;
	uint32_t rdata_count=0;
	NTSTATUS status;
	struct security_descriptor *lsd;

	SIVAL(param, 0, fnum);
	SIVAL(param, 4, sec_info);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_QUERY_SECURITY_DESC, 0, /* function, flags */
			   NULL, 0, 0, /* setup, length, max */
			   param, 8, 4, /* param, length, max */
			   NULL, 0, 0x10000, /* data, length, max */
			   NULL,	     /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, length */
			   NULL, 0, NULL,
			   &rdata, 0, &rdata_count);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("NT_TRANSACT_QUERY_SECURITY_DESC failed: %s\n",
			  nt_errstr(status)));
		goto cleanup;
	}

	status = unmarshall_sec_desc(mem_ctx, (uint8 *)rdata, rdata_count,
				     &lsd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("unmarshall_sec_desc failed: %s\n",
			   nt_errstr(status)));
		goto cleanup;
	}

	if (sd != NULL) {
		*sd = lsd;
	} else {
		TALLOC_FREE(lsd);
	}

 cleanup:

	TALLOC_FREE(rdata);

	return status;
}

NTSTATUS cli_query_secdesc(struct cli_state *cli, uint16_t fnum,
			   TALLOC_CTX *mem_ctx, struct security_descriptor **sd)
{
	uint32_t sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;

	return cli_query_security_descriptor(cli, fnum, sec_info, mem_ctx, sd);
}

/****************************************************************************
  set the security descriptor for a open file
 ****************************************************************************/
NTSTATUS cli_set_security_descriptor(struct cli_state *cli,
				     uint16_t fnum,
				     uint32_t sec_info,
				     const struct security_descriptor *sd)
{
	uint8_t param[8];
	uint8 *data;
	size_t len;
	NTSTATUS status;

	status = marshall_sec_desc(talloc_tos(), sd, &data, &len);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("marshall_sec_desc failed: %s\n",
			   nt_errstr(status)));
		return status;
	}

	SIVAL(param, 0, fnum);
	SIVAL(param, 4, sec_info);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_SET_SECURITY_DESC, 0,
			   NULL, 0, 0, /* setup */
			   param, 8, 0, /* param */
			   data, len, 0, /* data */
			   NULL,	 /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup */
			   NULL, 0, NULL, /* rparam */
			   NULL, 0, NULL); /* rdata */
	TALLOC_FREE(data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to send NT_TRANSACT_SET_SECURITY_DESC: %s\n",
			  nt_errstr(status)));
	}
	return status;
}

NTSTATUS cli_set_secdesc(struct cli_state *cli, uint16_t fnum,
			 const struct security_descriptor *sd)
{
	uint32_t sec_info = 0;

	if (sd->dacl || (sd->type & SEC_DESC_DACL_PRESENT)) {
		sec_info |= SECINFO_DACL;
	}
	if (sd->sacl || (sd->type & SEC_DESC_SACL_PRESENT)) {
		sec_info |= SECINFO_SACL;
	}
	if (sd->owner_sid) {
		sec_info |= SECINFO_OWNER;
	}
	if (sd->group_sid) {
		sec_info |= SECINFO_GROUP;
	}

	return cli_set_security_descriptor(cli, fnum, sec_info, sd);
}
