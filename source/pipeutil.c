
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB utility routines
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"

extern int DEBUGLEVEL;

/* this function is due to be replaced */
void initrpcreply(char *inbuf, char *q)
{
	uint32 callid;

	SCVAL(q, 0, 5); q++; /* RPC version 5 */
	SCVAL(q, 0, 0); q++; /* minor version 0 */
	SCVAL(q, 0, 2); q++; /* RPC response packet */
	SCVAL(q, 0, 3); q++; /* first frag + last frag */
	RSIVAL(q, 0, 0x10000000); q += 4; /* packed data representation */
	RSSVAL(q, 0, 0); q += 2; /* fragment length, fill in later */
	SSVAL(q, 0, 0); q += 2; /* authentication length */
	callid = RIVAL(inbuf, 12);
	RSIVAL(q, 0, callid); q += 4; /* call identifier - match incoming RPC */
	SIVAL(q, 0, 0x18); q += 4; /* allocation hint (no idea) */
	SSVAL(q, 0, 0); q += 2; /* presentation context identifier */
	SCVAL(q, 0, 0); q++; /* cancel count */
	SCVAL(q, 0, 0); q++; /* reserved */
}

/* this function is due to be replaced */
void endrpcreply(char *inbuf, char *q, int datalen, int rtnval, int *rlen)
{
	SSVAL(q, 8, datalen + 4);
	SIVAL(q,0x10,datalen+4-0x18); /* allocation hint */
	SIVAL(q, datalen, rtnval);
	*rlen = datalen + 4;
	{ int fd; fd = open("/tmp/rpc", O_RDWR); write(fd, q, datalen + 4); }
}

/* RID username mapping function.  just for fun, it maps to the unix uid */
uint32 name_to_rid(char *user_name)
{
    struct passwd *pw = Get_Pwnam(user_name, False);
    if (!pw)
	{
      DEBUG(1,("Username %s is invalid on this system\n", user_name));
      return (uint32)(-1);
    }

    return (uint32)(pw->pw_uid);
}


/* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
char *dom_sid_to_string(DOM_SID *sid)
{
  static pstring sidstr;
  char subauth[16];
  int i;
  uint32 ia = (sid->id_auth[0]) +
              (sid->id_auth[1] << 8 ) +
              (sid->id_auth[2] << 16) +
              (sid->id_auth[3] << 24);

  sprintf(sidstr, "S-%d-%d", sid->sid_no, ia);

  for (i = 0; i < sid->num_auths; i++)
  {
    sprintf(subauth, "-%d", sid->sub_auths[i]);
    strcat(sidstr, subauth);
  }

  DEBUG(5,("dom_sid_to_string returning %s\n", sidstr));
  return sidstr;
}

/* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
/* identauth >= 2^32 can be detected because it will be specified in hex */
void make_dom_sid(DOM_SID *sid, char *domsid)
{
	int identauth;
	char *p;

	if (sid == NULL) return;

	if (domsid == NULL)
	{
		DEBUG(4,("netlogon domain SID: none\n"));
		sid->sid_no = 0;
		sid->num_auths = 0;
		return;
	}
		
	DEBUG(4,("netlogon domain SID: %s\n", domsid));

	/* assume, but should check, that domsid starts "S-" */
	p = strtok(domsid+2,"-");
	sid->sid_no = atoi(p);

	/* identauth in decimal should be <  2^32 */
	/* identauth in hex     should be >= 2^32 */
	identauth = atoi(strtok(0,"-"));

	DEBUG(4,("netlogon rev %d\n", sid->sid_no));
	DEBUG(4,("netlogon %s ia %d\n", p, identauth));

	sid->id_auth[0] = 0;
	sid->id_auth[1] = 0;
	sid->id_auth[2] = (identauth & 0xff000000) >> 24;
	sid->id_auth[3] = (identauth & 0x00ff0000) >> 16;
	sid->id_auth[4] = (identauth & 0x0000ff00) >> 8;
	sid->id_auth[5] = (identauth & 0x000000ff);

	sid->num_auths = 0;

	while ((p = strtok(0, "-")) != NULL)
	{
		sid->sub_auths[sid->num_auths++] = atoi(p);
	}
}

void create_rpc_reply(RPC_HDR *hdr, uint32 call_id, int data_len)
{
	if (hdr == NULL) return;

	hdr->major        = 5;               /* RPC version 5 */
	hdr->minor        = 0;               /* minor version 0 */
	hdr->pkt_type     = 2;               /* RPC response packet */
	hdr->frag         = 3;               /* first frag + last frag */
	hdr->pack_type    = 0x10;            /* packed data representation */
	hdr->frag_len     = data_len;        /* fragment length, fill in later */
	hdr->auth_len     = 0;               /* authentication length */
	hdr->call_id      = call_id;         /* call identifier - match incoming RPC */
	hdr->alloc_hint   = data_len - 0x18; /* allocation hint (no idea) */
	hdr->context_id   = 0;               /* presentation context identifier */
	hdr->cancel_count = 0;               /* cancel count */
	hdr->reserved     = 0;               /* reserved */
}

int make_rpc_reply(char *inbuf, char *q, int data_len)
{
	uint32 callid = IVAL(inbuf, 12);
	RPC_HDR hdr;

	create_rpc_reply(&hdr, callid, data_len);
	return smb_io_rpc_hdr(False, &hdr, q, q, 4, 0) - q;
}

void make_uni_hdr(UNIHDR *hdr, int max_len, int len, uint16 terminate)
{
	hdr->uni_max_len = max_len;
	hdr->uni_str_len = len;
	hdr->undoc       = terminate;
}

void make_uni_hdr2(UNIHDR2 *hdr, int max_len, int len, uint16 terminate)
{
	make_uni_hdr(&(hdr->unihdr), max_len, len, terminate);
	hdr->undoc_buffer = len > 0 ? 1 : 0;
}

void make_unistr(UNISTR *str, char *buf)
{
	/* store the string (null-terminated copy) */
	PutUniCode((char *)(str->buffer), buf);
}

void make_unistr2(UNISTR2 *str, char *buf, int len)
{
	/* set up string lengths. add one if string is not null-terminated */
	str->uni_max_len = len;
	str->undoc       = 0;
	str->uni_str_len = len;

	/* store the string (null-terminated copy) */
	PutUniCode((char *)str->buffer, buf);
}

void make_dom_rid2(DOM_RID2 *rid2, uint32 rid)
{
	rid2->type    = 0x5;
	rid2->undoc   = 0x5;
	rid2->rid     = rid;
	rid2->rid_idx = 0;
}

void make_dom_sid2(DOM_SID2 *sid2, char *sid_str)
{
	int len_sid_str = strlen(sid_str);

	sid2->type = 0x5;
	sid2->undoc = 0;
	make_uni_hdr2(&(sid2->hdr), len_sid_str, len_sid_str, 0);
	make_unistr  (&(sid2->str), sid_str);
}
