/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines to synchronise browse lists
   Copyright (C) Andrew Tridgell 1994-1995
   
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

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern pstring myname;

extern int name_type;
extern int max_protocol;
extern struct in_addr dest_ip;
extern int pid;
extern int gid;
extern int uid;
extern int mid;
extern BOOL got_pass;
extern BOOL have_ip;
extern pstring workgroup;
extern pstring service;
extern pstring desthost;
extern BOOL connect_as_ipc;

/****************************************************************************
fudge for getpass function
****************************************************************************/
char *getsmbpass(char *pass)
{
	return "dummy"; /* return anything: it should be ignored anyway */
}

/****************************************************************************
adds information retrieved from a NetServerEnum call
****************************************************************************/
static BOOL add_info(struct subnet_record *d, struct work_record *work, int servertype)
{
  char *rparam = NULL;
  char *rdata = NULL;
  int rdrcnt,rprcnt;
  char *p;
  pstring param;
  int uLevel = 1;
  int count = -1;
  
  /* now send a SMBtrans command with api ServerEnum? */
  p = param;
  SSVAL(p,0,0x68); /* api number */
  p += 2;
  strcpy(p,"WrLehDz");
  p = skip_string(p,1);
  
  strcpy(p,"B16BBDz");
  
  p = skip_string(p,1);
  SSVAL(p,0,uLevel);
  SSVAL(p,2,0x2000); /* buf length */
  p += 4;
  SIVAL(p,0,servertype);
  p += 4;
  
  strcpy(p, work->work_group);
  p = skip_string(p,1);
  
  if (cli_call_api(PTR_DIFF(p,param),0, 8,10000,
		   &rprcnt,&rdrcnt, param,NULL,
		   &rparam,&rdata))
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;
      
      if (res == 0)
	{
	  count=SVAL(rparam,4);
	  p = rdata;
	  
	  for (i = 0;i < count;i++, p += 26)
	    {
	      char *sname = p;
	      uint32 stype = IVAL(p,18);
	      int comment_offset = IVAL(p,22) & 0xFFFF;
	      char *cmnt = comment_offset?(rdata+comment_offset-converter):"";
	      
	      struct work_record *w = work;
	      
	      DEBUG(4, ("\t%-16.16s     %08x    %s\n", sname, stype, cmnt));
	      
	      if (stype & SV_TYPE_DOMAIN_ENUM)
		{
		  /* creates workgroup on remote subnet */
		  if ((w = find_workgroupstruct(d,sname,True)))
		    {
		      announce_request(w, d->bcast_ip);
		    }
		}
	      
          if (w)
	        add_server_entry(d,w,sname,stype,lp_max_ttl(),cmnt,False);
	    }
	}
    }
  
  if (rparam) free(rparam);
  if (rdata) free(rdata);
  
  return(True);
}


/*******************************************************************
  synchronise browse lists with another browse server.

  log in on the remote server's SMB port to their IPC$ service,
  do a NetServerEnum and update our server and workgroup databases.
  ******************************************************************/
void sync_browse_lists(struct subnet_record *d, struct work_record *work,
		char *name, int nm_type, struct in_addr ip, BOOL local)
{
  uint32 local_type = local ? SV_TYPE_LOCAL_LIST_ONLY : 0;

  if (!d || !work || !AM_MASTER(work)) return;

  pid = getpid();
  uid = getuid();
  gid = getgid();
  mid = pid + 100;
  name_type = nm_type;
  
  got_pass = True;
  
  DEBUG(4,("sync browse lists with %s for %s %s\n",
	    work->work_group, name, inet_ntoa(ip)));
  
  strcpy(workgroup,work->work_group);
  strcpy(desthost,name);
  dest_ip = ip;
  
  if (zero_ip(dest_ip)) return;
  have_ip = True;
  
  connect_as_ipc = True;
  
  /* connect as server and get domains, then servers */
  
  sprintf(service,"\\\\%s\\IPC$", name);
  strupper(service);
  
  if (cli_open_sockets(SMB_PORT))
    {
      if (cli_send_login(NULL,NULL,True,True))
	{
	  add_info(d, work, local_type|SV_TYPE_DOMAIN_ENUM);
	  add_info(d, work, local_type|(SV_TYPE_ALL&
                      ~(SV_TYPE_DOMAIN_ENUM|SV_TYPE_LOCAL_LIST_ONLY)));
	}
      
      close_sockets();
    }
}
