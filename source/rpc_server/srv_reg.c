
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Lars Kneschke                     2000.
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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#if 0
/****************************************************************************
  set reg name 
****************************************************************************/
static BOOL set_policy_reg_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = strdup(name);
	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Registry setting policy name=%s\n", name));
			return True;
		}
		free(dev);
	}

	DEBUG(3,("Error setting policy name=%s\n", name));
	return False;
}
#endif
/****************************************************************************
  get reg name 
****************************************************************************/
static BOOL get_policy_reg_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = (char*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		fstrcpy(name, dev);
		DEBUG(5,("getting policy reg name=%s\n", name));
		return True;
	}

	DEBUG(3,("Error getting policy reg name\n"));
	return False;
}

/*******************************************************************
 api_reg_close
 ********************************************************************/
static BOOL api_reg_close( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
        REG_Q_CLOSE q_r;
        REG_R_CLOSE r_u;
        ZERO_STRUCT(q_r);
        ZERO_STRUCT(r_u);
 
        /* grab the reg unknown 1 */
        if (!reg_io_q_close("", &q_r, data, 0))
	{
		return False;
	}

 
        memcpy(&r_u.pol, &q_r.pol, sizeof(POLICY_HND));
 
        /* construct reply.  always indicate success */
        r_u.status = _reg_close(&r_u.pol);
 
        /* store the response in the SMB stream */
        return reg_io_r_close("", &r_u, rdata, 0);
}            

/*******************************************************************
 api_reg_open
 ********************************************************************/
static BOOL api_reg_open( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
        REG_Q_OPEN_HKLM q_u;
        REG_R_OPEN_HKLM r_u;
        ZERO_STRUCT(q_u);
        ZERO_STRUCT(r_u);
 
        /* grab the reg open */
        if (!reg_io_q_open_hklm("", &q_u, data, 0))
	{
		return False;
	}

 
        r_u.status = _reg_open(&r_u.pol, q_u.access_mask);
 
        /* store the response in the SMB stream */
        return reg_io_r_open_hklm("", &r_u, rdata, 0); 
}

/*******************************************************************
 api_reg_open_entry
 ********************************************************************/
static BOOL api_reg_open_entry( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	uint32 status;
	
	POLICY_HND entry_pol;
	REG_Q_OPEN_ENTRY q_u;
	REG_R_OPEN_ENTRY r_u; 
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the reg open entry */
	if (!reg_io_q_open_entry("", &q_u, data, 0))
	{
		return False;
	}

	/* construct reply. */
	status = _reg_open_entry(&q_u.pol,&q_u.uni_name,q_u.unknown_0,q_u.access_mask,&entry_pol);
	
	make_reg_r_open_entry(&r_u, &entry_pol, status);

	/* store the response in the SMB stream */
	return reg_io_r_open_entry("", &r_u, rdata, 0);	
}


/*******************************************************************
 api_reg_info
 ********************************************************************/
static BOOL api_reg_info( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	REG_R_INFO r_u;
	REG_Q_INFO q_u;
	BUFFER2 buf;

	uint32 status;
	uint32 type = 0xcafeface;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(buf);


	/* grab the reg unknown 0x11*/
	if (!reg_io_q_info("", &q_u, data, 0))
	{
		return False;
	}


	/* construct reply.  always indicate success */
	status = _reg_info(&q_u.pol, &buf, &type);

	make_reg_r_info(&r_u, &type, &buf, status);

	/* store the response in the SMB stream */
	return reg_io_r_info("", &r_u, rdata, 0);	
}


/*******************************************************************
 array of \PIPE\reg operations
 ********************************************************************/
static const struct api_struct api_reg_cmds[] =
{
	{ "REG_CLOSE"        , REG_CLOSE        , api_reg_close        },
	{ "REG_OPEN_ENTRY"   , REG_OPEN_ENTRY   , api_reg_open_entry   },
	{ "REG_OPEN"         , REG_OPEN_HKLM    , api_reg_open         },
	{ "REG_INFO"         , REG_INFO         , api_reg_info         },
	{ NULL,                0                , NULL                 }
};

/*******************************************************************
 receives a reg pipe and responds.
 ********************************************************************/
BOOL api_reg_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_reg_rpc", api_reg_cmds);
}

