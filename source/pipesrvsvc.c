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


BOOL api_srvsvcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
  uint16 opnum;
  char *q;
  int pkttype;
  extern pstring myname;
  char *servername;
  uint32 level;

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
      q = data + 0x18;
      servername = q + 16;
      q = skip_unicode_string(servername,1);
      if (strlen(unistr(servername)) % 2 == 0)
      q += 2;
     level = IVAL(q, 0); q += 4;
      /* ignore the rest for the moment */
      q = *rdata + 0x18;
      SIVAL(q, 0, level); q += 4;
      SIVAL(q, 0, 1); q += 4; /* switch value */
      SIVAL(q, 0, 2); q += 4;
      SIVAL(q, 0, 2); q += 4; /* number of entries */
      SIVAL(q, 0, 2); q += 4;
      endrpcreply(data, *rdata, q-*rdata, 0, rdata_len);
      break;

    case NETSERVERGETINFO:
    {
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

