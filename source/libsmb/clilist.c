/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client directory list routines
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#define NO_SYSLOG

#include "includes.h"


/****************************************************************************
interpret a long filename structure - this is mostly guesses at the moment
The length of the structure is returned
The structure of a long filename depends on the info level. 260 is used
by NT and 2 is used by OS/2
****************************************************************************/
static int interpret_long_filename(int level,char *p,file_info *finfo)
{
	extern file_info def_finfo;

	if (finfo)
		memcpy(finfo,&def_finfo,sizeof(*finfo));

	switch (level)
		{
		case 1: /* OS/2 understands this */
			if (finfo) {
				/* these dates are converted to GMT by make_unix_date */
				finfo->ctime = make_unix_date2(p+4);
				finfo->atime = make_unix_date2(p+8);
				finfo->mtime = make_unix_date2(p+12);
				finfo->size = IVAL(p,16);
				finfo->mode = CVAL(p,24);
				pstrcpy(finfo->name,p+27);
				dos_to_unix(finfo->name,True);
			}
			return(28 + CVAL(p,26));

		case 2: /* this is what OS/2 uses mostly */
			if (finfo) {
				/* these dates are converted to GMT by make_unix_date */
				finfo->ctime = make_unix_date2(p+4);
				finfo->atime = make_unix_date2(p+8);
				finfo->mtime = make_unix_date2(p+12);
				finfo->size = IVAL(p,16);
				finfo->mode = CVAL(p,24);
				pstrcpy(finfo->name,p+31);
				dos_to_unix(finfo->name,True);
			}
			return(32 + CVAL(p,30));

			/* levels 3 and 4 are untested */
		case 3:
			if (finfo) {
				/* these dates are probably like the other ones */
				finfo->ctime = make_unix_date2(p+8);
				finfo->atime = make_unix_date2(p+12);
				finfo->mtime = make_unix_date2(p+16);
				finfo->size = IVAL(p,20);
				finfo->mode = CVAL(p,28);
				pstrcpy(finfo->name,p+33);
				dos_to_unix(finfo->name,True);
			}
			return(SVAL(p,4)+4);
			
		case 4:
			if (finfo) {
				/* these dates are probably like the other ones */
				finfo->ctime = make_unix_date2(p+8);
				finfo->atime = make_unix_date2(p+12);
				finfo->mtime = make_unix_date2(p+16);
				finfo->size = IVAL(p,20);
				finfo->mode = CVAL(p,28);
				pstrcpy(finfo->name,p+37);
				dos_to_unix(finfo->name,True);
			}
			return(SVAL(p,4)+4);
			
		case 260: /* NT uses this, but also accepts 2 */
			if (finfo) {
				int ret = SVAL(p,0);
				int namelen, slen;
				p += 4; /* next entry offset */
				p += 4; /* fileindex */
				
				/* these dates appear to arrive in a
				   weird way. It seems to be localtime
				   plus the serverzone given in the
				   initial connect. This is GMT when
				   DST is not in effect and one hour
				   from GMT otherwise. Can this really
				   be right??

				   I suppose this could be called
				   kludge-GMT. Is is the GMT you get
				   by using the current DST setting on
				   a different localtime. It will be
				   cheap to calculate, I suppose, as
				   no DST tables will be needed */

				finfo->ctime = interpret_long_date(p); p += 8;
				finfo->atime = interpret_long_date(p); p += 8;
				finfo->mtime = interpret_long_date(p); p += 8; p += 8;
				finfo->size = IVAL(p,0); p += 8;
				p += 8; /* alloc size */
				finfo->mode = CVAL(p,0); p += 4;
				namelen = IVAL(p,0); p += 4;
				p += 4; /* EA size */
				slen = SVAL(p, 0);
				p += 2; 
				if (p[1] == 0 && slen > 1) {
					/* NT has stuffed up again */
					unistr_to_dos(finfo->short_name, p, slen/2);
				} else {
					strncpy(finfo->short_name, p, 12);
					finfo->short_name[12] = 0;
				}
				p += 24; /* short name? */	  
				StrnCpy(finfo->name,p,MIN(sizeof(finfo->name)-1,namelen));
				dos_to_unix(finfo->name,True);
				return(ret);
			}
			return(SVAL(p,0));
		}
	
	DEBUG(1,("Unknown long filename format %d\n",level));
	return(SVAL(p,0));
}


/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
int cli_list(struct cli_state *cli,const char *Mask,uint16 attribute, 
	     void (*fn)(file_info *, const char *))
{
	int max_matches = 512;
	/* NT uses 260, OS/2 uses 2. Both accept 1. */
	int info_level = cli->protocol<PROTOCOL_NT1?1:260; 
	char *p, *p2;
	pstring mask;
	file_info finfo;
	int i;
	char *dirlist = NULL;
	int dirlist_len = 0;
	int total_received = -1;
	BOOL First = True;
	int ff_searchcount=0;
	int ff_eos=0;
	int ff_lastname=0;
	int ff_dir_handle=0;
	int loop_count = 0;
	char *rparam=NULL, *rdata=NULL;
	int param_len, data_len;	
	uint16 setup;
	pstring param;
	
	pstrcpy(mask,Mask);
	unix_to_dos(mask,True);
	
	while (ff_eos == 0) {
		loop_count++;
		if (loop_count > 200) {
			DEBUG(0,("Error: Looping in FIND_NEXT??\n"));
			break;
		}

		param_len = 12+strlen(mask)+1;

		if (First) {
			setup = TRANSACT2_FINDFIRST;
			SSVAL(param,0,attribute); /* attribute */
			SSVAL(param,2,max_matches); /* max count */
			SSVAL(param,4,4+2);	/* resume required + close on end */
			SSVAL(param,6,info_level); 
			SIVAL(param,8,0);
			pstrcpy(param+12,mask);
		} else {
			setup = TRANSACT2_FINDNEXT;
			SSVAL(param,0,ff_dir_handle);
			SSVAL(param,2,max_matches); /* max count */
			SSVAL(param,4,info_level); 
			SIVAL(param,6,0); /* ff_resume_key */
			SSVAL(param,10,8+4+2);	/* continue + resume required + close on end */
			pstrcpy(param+12,mask);

			DEBUG(5,("hand=0x%X ff_lastname=%d mask=%s\n",
				 ff_dir_handle,ff_lastname,mask));
		}

		if (!cli_send_trans(cli, SMBtrans2, 
				    NULL, 0,                /* Name, length */
				    -1, 0,                  /* fid, flags */
				    &setup, 1, 0,           /* setup, length, max */
				    param, param_len, 10,   /* param, length, max */
				    NULL, 0, 
				    cli->max_xmit /* data, length, max */
				    )) {
			break;
		}

		if (!cli_receive_trans(cli, SMBtrans2, 
				       &rparam, &param_len,
				       &rdata, &data_len)) {
			/* we need to work around a Win95 bug - sometimes
			   it gives ERRSRV/ERRerror temprarily */
			uint8 eclass;
			uint32 ecode;
			cli_error(cli, &eclass, &ecode, NULL);
			if (eclass != ERRSRV || ecode != ERRerror) break;
			msleep(100);
			continue;
		}

		if (total_received == -1) total_received = 0;

		/* parse out some important return info */
		p = rparam;
		if (First) {
			ff_dir_handle = SVAL(p,0);
			ff_searchcount = SVAL(p,2);
			ff_eos = SVAL(p,4);
			ff_lastname = SVAL(p,8);
		} else {
			ff_searchcount = SVAL(p,0);
			ff_eos = SVAL(p,2);
			ff_lastname = SVAL(p,6);
		}

		if (ff_searchcount == 0) 
			break;

		/* point to the data bytes */
		p = rdata;

		/* we might need the lastname for continuations */
		if (ff_lastname > 0) {
			switch(info_level)
				{
				case 260:
					StrnCpy(mask,p+ff_lastname,
						MIN(sizeof(mask)-1,data_len-ff_lastname));
					break;
				case 1:
					pstrcpy(mask,p + ff_lastname + 1);
					break;
				}
		} else {
			pstrcpy(mask,"");
		}
 
		dos_to_unix(mask, True);
 
		/* and add them to the dirlist pool */
		dirlist = Realloc(dirlist,dirlist_len + data_len);

		if (!dirlist) {
			DEBUG(0,("Failed to expand dirlist\n"));
			break;
		}

		/* put in a length for the last entry, to ensure we can chain entries 
		   into the next packet */
		for (p2=p,i=0;i<(ff_searchcount-1);i++)
			p2 += interpret_long_filename(info_level,p2,NULL);
		SSVAL(p2,0,data_len - PTR_DIFF(p2,p));

		/* grab the data for later use */
		memcpy(dirlist+dirlist_len,p,data_len);
		dirlist_len += data_len;

		total_received += ff_searchcount;

		if (rdata) free(rdata); rdata = NULL;
		if (rparam) free(rparam); rparam = NULL;
		
		DEBUG(3,("received %d entries (eos=%d)\n",
			 ff_searchcount,ff_eos));

		if (ff_searchcount > 0) loop_count = 0;

		First = False;
	}

	for (p=dirlist,i=0;i<total_received;i++) {
		p += interpret_long_filename(info_level,p,&finfo);
		fn(&finfo, Mask);
	}

	/* free up the dirlist buffer */
	if (dirlist) free(dirlist);
	return(total_received);
}



/****************************************************************************
interpret a short filename structure
The length of the structure is returned
****************************************************************************/
static int interpret_short_filename(char *p,file_info *finfo)
{
	extern file_info def_finfo;

	*finfo = def_finfo;

	finfo->mode = CVAL(p,21);
	
	/* this date is converted to GMT by make_unix_date */
	finfo->ctime = make_unix_date(p+22);
	finfo->mtime = finfo->atime = finfo->ctime;
	finfo->size = IVAL(p,26);
	pstrcpy(finfo->name,p+30);
	if (strcmp(finfo->name, "..") && strcmp(finfo->name, "."))
		fstrcpy(finfo->short_name,finfo->name);
	
	return(DIR_STRUCT_SIZE);
}


/****************************************************************************
  do a directory listing, calling fn on each file found
  this uses the old SMBsearch interface. It is needed for testing Samba,
  but should otherwise not be used
  ****************************************************************************/
int cli_list_old(struct cli_state *cli,const char *Mask,uint16 attribute, 
		 void (*fn)(file_info *, const char *))
{
	char *p;
	int received = 0;
	BOOL first = True;
	char status[21];
	int num_asked = (cli->max_xmit - 100)/DIR_STRUCT_SIZE;
	int num_received = 0;
	int i;
	char *dirlist = NULL;
	pstring mask;
	
	ZERO_ARRAY(status);

	pstrcpy(mask,Mask);
  
	while (1) {
		memset(cli->outbuf,'\0',smb_size);
		memset(cli->inbuf,'\0',smb_size);

		if (first)	
			set_message(cli->outbuf,2,5 + strlen(mask),True);
		else
			set_message(cli->outbuf,2,5 + 21,True);

		CVAL(cli->outbuf,smb_com) = SMBffirst;

		SSVAL(cli->outbuf,smb_tid,cli->cnum);
		cli_setup_packet(cli);

		SSVAL(cli->outbuf,smb_vwv0,num_asked);
		SSVAL(cli->outbuf,smb_vwv1,attribute);
  
		p = smb_buf(cli->outbuf);
		*p++ = 4;
      
		if (first)
			pstrcpy(p,mask);
		else
			pstrcpy(p,"");
		p += strlen(p) + 1;
      
		*p++ = 5;
		if (first) {
			SSVAL(p,0,0);
		} else {
			SSVAL(p,0,21);
			p += 2;
			memcpy(p,status,21);
		}

		cli_send_smb(cli);
		if (!cli_receive_smb(cli)) break;

		received = SVAL(cli->inbuf,smb_vwv0);
		if (received <= 0) break;

		first = False;

		dirlist = Realloc(dirlist,(num_received + received)*DIR_STRUCT_SIZE);

		if (!dirlist) 
			return 0;

		p = smb_buf(cli->inbuf) + 3;

		memcpy(dirlist+num_received*DIR_STRUCT_SIZE,
		       p,received*DIR_STRUCT_SIZE);
		
		memcpy(status,p + ((received-1)*DIR_STRUCT_SIZE),21);
		
		num_received += received;
		
		if (CVAL(cli->inbuf,smb_rcls) != 0) break;
	}

	if (!first) {
		memset(cli->outbuf,'\0',smb_size);
		memset(cli->inbuf,'\0',smb_size);

		set_message(cli->outbuf,2,5 + 21,True);
		CVAL(cli->outbuf,smb_com) = SMBfclose;
		SSVAL(cli->outbuf,smb_tid,cli->cnum);
		cli_setup_packet(cli);

		SSVAL(cli->outbuf, smb_vwv0, 0); /* find count? */
		SSVAL(cli->outbuf, smb_vwv1, attribute);

		p = smb_buf(cli->outbuf);
		*p++ = 4;
		fstrcpy(p, "");
		p += strlen(p) + 1;
		*p++ = 5;
		SSVAL(p, 0, 21);
		p += 2;
		memcpy(p,status,21);
		
		cli_send_smb(cli);
		if (!cli_receive_smb(cli)) {
			DEBUG(0,("Error closing search: %s\n",smb_errstr(cli->inbuf)));
		}
	}

	for (p=dirlist,i=0;i<num_received;i++) {
		file_info finfo;
		p += interpret_short_filename(p,&finfo);
		fn(&finfo, Mask);
	}

	if (dirlist) free(dirlist);
	return(num_received);
}
