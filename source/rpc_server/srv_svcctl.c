
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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
#include "nterr.h"

extern int DEBUGLEVEL;


/*******************************************************************
 svc_reply_unknown_1
 ********************************************************************/
static void svc_reply_close(SVC_Q_CLOSE *q_r,
				prs_struct *rdata)
{
	SVC_R_CLOSE r_u;

	/* set up the REG unknown_1 response */
	bzero(r_u.pol.data, POL_HND_SIZE);

	/* close the policy handle */
	if (close_lsa_policy_hnd(&(q_r->pol)))
	{
		r_u.status = 0;
	}
	else
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_INVALID;
	}

	DEBUG(5,("svc_unknown_1: %d\n", __LINE__));

	/* store the response in the SMB stream */
	svc_io_r_close("", &r_u, rdata, 0);

	DEBUG(5,("svc_unknown_1: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_close
 ********************************************************************/
static void api_svc_close( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_CLOSE q_r;
	svc_io_q_close("", &q_r, data, 0);
	svc_reply_close(&q_r, rdata);
}


/*******************************************************************
 svc_reply_open_sc_man
 ********************************************************************/
static void svc_reply_open_sc_man(SVC_Q_OPEN_SC_MAN *q_u,
				prs_struct *rdata)
{
	uint32 status     = 0;
	POLICY_HND pol;
	SVC_R_OPEN_SC_MAN r_u;
	fstring name;

	DEBUG(5,("svc_open_sc_man: %d\n", __LINE__));

	if (status == 0x0 && !open_lsa_policy_hnd(&pol))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	fstrcpy(name, unistr2_to_str(&q_u->uni_srv_name));

	if (status == 0x0)
	{
		DEBUG(5,("svc_open_sc_man: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
	}

	if (status == 0x0 && !set_lsa_policy_reg_name(&pol, name))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	make_svc_r_open_sc_man(&r_u, &pol, status);

	/* store the response in the SMB stream */
	svc_io_r_open_sc_man("", &r_u, rdata, 0);

	DEBUG(5,("svc_open_sc_man: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_open_sc_man
 ********************************************************************/
static void api_svc_open_sc_man( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_OPEN_SC_MAN q_u;
	svc_io_q_open_sc_man("", &q_u, data, 0);
	svc_reply_open_sc_man(&q_u, rdata);
}

/*******************************************************************
 array of \PIPE\svcctl operations
 ********************************************************************/
static struct api_struct api_svc_cmds[] =
{
	{ "SVC_CLOSE"        , SVC_CLOSE        , api_svc_close        },
	{ "SVC_OPEN_SC_MAN"  , SVC_OPEN_SC_MAN  , api_svc_open_sc_man  },
	{ NULL,                0                , NULL                 }
};

/*******************************************************************
 receives a svcctl pipe and responds.
 ********************************************************************/
BOOL api_svcctl_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_svc_rpc", api_svc_cmds, data);
}

