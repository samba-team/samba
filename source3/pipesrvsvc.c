/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB reply routines - srvsvc pipe
   Copyright (C) Andrew Tridgell 1992-1997,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997.
   Copyright (C) Paul Ashton  1997.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "includes.h"
#include "trans2.h"
#include "nterr.h"

extern int DEBUGLEVEL;


/*******************************************************************
********************************************************************/
static void make_srv_share_info1_str(SH_INFO_1_STR *sh1, char *net_name, char *remark)
{
	if (sh1 == NULL) return;

	DEBUG(5,("make_srv_share_info1_str: %s %s\n", net_name, remark));

	make_unistr2(&(sh1->uni_netname), net_name, strlen(net_name)+1);
	make_unistr2(&(sh1->uni_remark ), remark  , strlen(remark  )+1);
}

/*******************************************************************
********************************************************************/
static void make_srv_share_info1(SH_INFO_1 *sh1, char *net_name, uint32 type, char *remark)
{
	if (sh1 == NULL) return;

	DEBUG(5,("make_srv_share_info1_str: %s %8x %s\n", net_name, type, remark));

	sh1->ptr_netname = net_name != NULL ? 1 : 0;
	sh1->type        = type;
	sh1->ptr_remark  = remark   != NULL ? 1 : 0;
}

/*******************************************************************
fill in a share info level 1 structure.

this function breaks the rule that i'd like to be in place, namely
it doesn't receive its data as arguments: it has to call lp_xxxx()
functions itself.  yuck.

this function is identical to api_RNetShareEnum().  maybe it even
generates the same output!  (too much to hope for, really...)

********************************************************************/
static void make_srv_share_1_ctr(SHARE_INFO_1_CTR *ctr)
{
	int snum;
	int num_entries = 0;
	int svcs = lp_numservices();

	if (ctr == NULL) return;

	DEBUG(5,("make_srv_share_1_ctr\n"));

	for (snum = 0; snum < svcs && num_entries < MAX_SHARE_ENTRIES; num_entries++, snum++)
	{
		int len_net_name;
		pstring net_name;
		pstring remark;
		uint32 type;

		if (lp_browseable(snum) && lp_snum_ok(snum))
		{
			/* see ipc.c:fill_share_info() */

			pstrcpy(net_name, lp_servicename(snum));
			pstrcpy(remark  , lp_comment    (snum));
			len_net_name = strlen(net_name);

			/* work out the share type */
			type = STYPE_DISKTREE;
			
			if (lp_print_ok(snum))             type = STYPE_PRINTQ;
			if (strequal("IPC$", net_name))    type = STYPE_IPC;
			if (net_name[len_net_name] == '$') type |= STYPE_HIDDEN;

			make_srv_share_info1    (&(ctr->info_1    [num_entries]), net_name, type, remark);
			make_srv_share_info1_str(&(ctr->info_1_str[num_entries]), net_name,       remark);
		}
	}

	ctr->num_entries_read  = num_entries;
	ctr->ptr_share_info    = num_entries > 0 ? 1 : 0;
	ctr->num_entries_read2 = num_entries;
	ctr->num_entries_read3 = num_entries;
	ctr->padding           = 0;
}

/*******************************************************************
********************************************************************/
static void make_srv_net_share_enum(SRV_R_NET_SHARE_ENUM *r_n,
                             int share_level, int switch_value, int status)  
{
	DEBUG(5,("make_srv_net_share_enum: %d\n", __LINE__));

	r_n->share_level  = share_level;
	r_n->switch_value = switch_value;
	r_n->status       = status;

	switch (switch_value)
	{
		case 1:
		{
			make_srv_share_1_ctr(&(r_n->share.info1));
			r_n->ptr_share_info = r_n->share.info1.num_entries_read > 0 ? 1 : 0;
			break;
		}
		default:
		{
			DEBUG(5,("make_srv_net_share_enum: unsupported switch value %d\n",
			          switch_value));
			r_n->ptr_share_info = 0;
			break;
		}
	}
}

/*******************************************************************
********************************************************************/
static int srv_reply_net_share_enum(SRV_Q_NET_SHARE_ENUM *q_n,
				char *q, char *base,
				int status)
{
	SRV_R_NET_SHARE_ENUM r_n;

	DEBUG(5,("srv_net_share_enum: %d\n", __LINE__));

	/* set up the */
	make_srv_net_share_enum(&r_n, q_n->share_level, q_n->switch_value, status);

	/* store the response in the SMB stream */
	q = srv_io_r_net_share_enum(False, &r_n, q, base, 4, 0);

	DEBUG(5,("srv_srv_pwset: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
********************************************************************/
static void api_srv_net_share_info( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SRV_Q_NET_SHARE_ENUM q_n;

	/* grab the net share enum */
	srv_io_q_net_share_enum(True, &q_n, data + 0x18, data, 4, 0);

	/* XXXX push the reply buffer size up a bit, and hope it's sufficient */
	/* for the current maximum limit of 32 share entries */
	*rdata_len = 4096;
	*rdata = REALLOC(*rdata, *rdata_len);

	/* construct reply.  always indicate success */
	*rdata_len = srv_reply_net_share_enum(&q_n, *rdata + 0x18, *rdata, 0x0);
}


/*******************************************************************
receives a srvsvc pipe and responds.
********************************************************************/
BOOL api_srvsvcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
  uint16 opnum;
  char *q;
  int pkttype;
  extern pstring myname;

  opnum = SVAL(data,22);

  pkttype = CVAL(data, 2);
  if (pkttype == 0x0b) /* RPC BIND */
  {
    DEBUG(4,("srvsvc rpc bind %x\n",pkttype));
    LsarpcTNP1(data,rdata,rdata_len);
    return True;
  }

  DEBUG(4,("srvsvc TransactNamedPipe op %x\n",opnum));
  initrpcreply(data, *rdata);
  DEBUG(4,("srvsvc LINE %d\n",__LINE__));
  get_myname(myname,NULL);

  switch (opnum)
  {
    case NETSHAREENUM:
	{
	  api_srv_net_share_info( param, data, rdata, rdata_len);

      make_rpc_reply(data, *rdata, *rdata_len);
      break;
    }

    case NETSERVERGETINFO:
    {
      char *servername;
      uint32 level;
      UNISTR2 uni_str;
      q = data + 0x18;
      servername = q + 16;
      q = skip_unicode_string(servername,1);
      if (strlen(unistr(servername)) % 2 == 0)
	q += 2;
    level = IVAL(q, 0); q += 4;
     /* ignore the rest for the moment */
      q = *rdata + 0x18;
      SIVAL(q, 0, 101); q += 4; /* switch value */
      SIVAL(q, 0, 2); q += 4; /* bufptr */
      SIVAL(q, 0, 0x1f4); q += 4; /* platform id */
      SIVAL(q, 0, 2); q += 4; /* bufptr for name */
      SIVAL(q, 0, 5); q += 4; /* major version */
      SIVAL(q, 0, 4); q += 4; /* minor version == 5.4 */
      SIVAL(q, 0, 0x4100B); q += 4; /* type */
      SIVAL(q, 0, 2); q += 4; /* comment */
      make_unistr2(&uni_str, myname, strlen(myname));
      q = smb_io_unistr2(False, &uni_str, q, *rdata, 4, 0);

      make_unistr2(&uni_str, lp_serverstring(), strlen(lp_serverstring()));
      q = smb_io_unistr2(False, &uni_str, q, *rdata, 4, 0);

      q = align_offset(q, *rdata, 4);

      endrpcreply(data, *rdata, q-*rdata, 0, rdata_len);
      break;
    }
    default:
      DEBUG(4, ("srvsvc, unknown code: %lx\n", opnum));
  }
  return(True);
}

