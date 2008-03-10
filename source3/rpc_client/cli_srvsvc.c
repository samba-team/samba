/* 
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Jeremy Allison  2005.
   Copyright (C) Gerald (Jerry) Carter        2006.


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

WERROR rpccli_srvsvc_net_file_enum(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				uint32 file_level, const char *user_name,
				SRV_FILE_INFO_CTR *ctr,	int preferred_len,
				ENUM_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_FILE_ENUM q;
	SRV_R_NET_FILE_ENUM r;
	WERROR result = W_ERROR(ERRgeneral);
	fstring server;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->cli->desthost);
	strupper_m(server);

	init_srv_q_net_file_enum(&q, server, NULL, user_name, 
				 file_level, ctr, preferred_len, hnd);

	/* Marshall data and send request */

	CLI_DO_RPC_WERR(cli, mem_ctx, PI_SRVSVC, SRV_NET_FILE_ENUM,
		q, r,
		qbuf, rbuf,
		srv_io_q_net_file_enum,
		srv_io_r_net_file_enum,
		WERR_GENERAL_FAILURE);

	result = r.status;

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* copy the data over to the ctr */

	ZERO_STRUCTP(ctr);

	ctr->level = file_level;

	ctr->num_entries = ctr->num_entries2 = r.ctr.num_entries;
	
	switch(file_level) {
	case 3:
		if (ctr->num_entries) {
			if ( (ctr->file.info3 = TALLOC_ARRAY(mem_ctx, FILE_INFO_3, ctr->num_entries)) == NULL ) {
				return WERR_NOMEM;
			}

			memset(ctr->file.info3, 0, sizeof(FILE_INFO_3) * ctr->num_entries);
		} else {
			ctr->file.info3 = NULL;
		}

		for (i = 0; i < r.ctr.num_entries; i++) {
			FILE_INFO_3 *info3 = &ctr->file.info3[i];
			char *s;
			
			/* Copy pointer crap */

			memcpy(info3, &r.ctr.file.info3[i], sizeof(FILE_INFO_3));

			/* Duplicate strings */

			if ( (s = unistr2_to_ascii_talloc(mem_ctx, r.ctr.file.info3[i].path)) != NULL ) {
				info3->path = TALLOC_P( mem_ctx, UNISTR2 );
				init_unistr2(info3->path, s, UNI_STR_TERMINATE);
			}
		
			if ( (s = unistr2_to_ascii_talloc(mem_ctx, r.ctr.file.info3[i].user)) != NULL ) {
				info3->user = TALLOC_P( mem_ctx, UNISTR2 );
				init_unistr2(info3->user, s, UNI_STR_TERMINATE);
			}

		}		

		break;
	}

  done:
	return result;
}

