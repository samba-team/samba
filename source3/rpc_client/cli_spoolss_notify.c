/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald Carter                2001-2002,
   Copyright (C) Tim Potter                   2000-2002,
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Jean-Francois Micouleau      1999-2000.
   Copyright (C) Jeremy Allison                    2005.

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

/*
 * SPOOLSS Client RPC's used by servers as the notification
 * back channel.
 */

/*********************************************************************
 *********************************************************************/
 
WERROR rpccli_spoolss_rffpcnex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    POLICY_HND *pol, uint32 flags, uint32 options,
			    const char *localmachine, uint32 printerlocal,
			    SPOOL_NOTIFY_OPTION *option)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_RFFPCNEX q;
	SPOOL_R_RFFPCNEX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	make_spoolss_q_rffpcnex(
		&q, pol, flags, options, localmachine, printerlocal,
		option);

	/* Marshall data and send request */

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_RFFPCNEX,
		q, r,
		qbuf, rbuf,
		spoolss_io_q_rffpcnex,
		spoolss_io_r_rffpcnex,
		WERR_GENERAL_FAILURE );

	result = r.status;
	return result;
}
