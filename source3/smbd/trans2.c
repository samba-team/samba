/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB transaction2 handling
   Copyright (C) Jeremy Allison 1994-2001

   Extensively modified by Andrew Tridgell, 1995

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

extern int Protocol;
extern BOOL case_sensitive;
extern int smb_read_error;
extern fstring local_machine;
extern int global_oplock_break;
extern uint32 global_client_caps;
extern pstring global_myname;

/****************************************************************************
  Send the required number of replies back.
  We assume all fields other than the data fields are
  set correctly for the type of call.
  HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static int send_trans2_replies(char *outbuf, int bufsize, char *params, 
			       int paramsize, char *pdata, int datasize)
{
  /* As we are using a protocol > LANMAN1 then the max_send
     variable must have been set in the sessetupX call.
     This takes precedence over the max_xmit field in the
     global struct. These different max_xmit variables should
     be merged as this is now too confusing */

  extern int max_send;
  int data_to_send = datasize;
  int params_to_send = paramsize;
  int useable_space;
  char *pp = params;
  char *pd = pdata;
  int params_sent_thistime, data_sent_thistime, total_sent_thistime;
  int alignment_offset = 1; /* JRA. This used to be 3. Set to 1 to make netmon parse ok. */
  int data_alignment_offset = 0;

  /* Initially set the wcnt area to be 10 - this is true for all
     trans2 replies */
  set_message(outbuf,10,0,True);

  /* If there genuinely are no parameters or data to send just send
     the empty packet */
  if(params_to_send == 0 && data_to_send == 0)
  {
    if (!send_smb(smbd_server_fd(),outbuf))
      exit_server("send_trans2_replies: send_smb failed.");
    return 0;
  }

  /* When sending params and data ensure that both are nicely aligned */
  /* Only do this alignment when there is also data to send - else
     can cause NT redirector problems. */
  if (((params_to_send % 4) != 0) && (data_to_send != 0))
    data_alignment_offset = 4 - (params_to_send % 4);

  /* Space is bufsize minus Netbios over TCP header minus SMB header */
  /* The alignment_offset is to align the param bytes on an even byte
     boundary. NT 4.0 Beta needs this to work correctly. */
  useable_space = bufsize - ((smb_buf(outbuf)+
                    alignment_offset+data_alignment_offset) - 
                    outbuf);

  /* useable_space can never be more than max_send minus the
     alignment offset. */
  useable_space = MIN(useable_space, 
                      max_send - (alignment_offset+data_alignment_offset));


  while (params_to_send || data_to_send)
  {
    /* Calculate whether we will totally or partially fill this packet */
    total_sent_thistime = params_to_send + data_to_send + 
                            alignment_offset + data_alignment_offset;
    /* We can never send more than useable_space */
    /*
     * Note that 'useable_space' does not include the alignment offsets,
     * but we must include the alignment offsets in the calculation of
     * the length of the data we send over the wire, as the alignment offsets
     * are sent here. Fix from Marc_Jacobsen@hp.com.
     */
    total_sent_thistime = MIN(total_sent_thistime, useable_space+
			        alignment_offset + data_alignment_offset);

    set_message(outbuf, 10, total_sent_thistime, True);

    /* Set total params and data to be sent */
    SSVAL(outbuf,smb_tprcnt,paramsize);
    SSVAL(outbuf,smb_tdrcnt,datasize);

    /* Calculate how many parameters and data we can fit into
       this packet. Parameters get precedence */

    params_sent_thistime = MIN(params_to_send,useable_space);
    data_sent_thistime = useable_space - params_sent_thistime;
    data_sent_thistime = MIN(data_sent_thistime,data_to_send);

    SSVAL(outbuf,smb_prcnt, params_sent_thistime);

    /* smb_proff is the offset from the start of the SMB header to the
       parameter bytes, however the first 4 bytes of outbuf are
       the Netbios over TCP header. Thus use smb_base() to subtract
       them from the calculation */

    SSVAL(outbuf,smb_proff,((smb_buf(outbuf)+alignment_offset) - smb_base(outbuf)));

    if(params_sent_thistime == 0)
      SSVAL(outbuf,smb_prdisp,0);
    else
      /* Absolute displacement of param bytes sent in this packet */
      SSVAL(outbuf,smb_prdisp,pp - params);

    SSVAL(outbuf,smb_drcnt, data_sent_thistime);
    if(data_sent_thistime == 0)
    {
      SSVAL(outbuf,smb_droff,0);
      SSVAL(outbuf,smb_drdisp, 0);
    }
    else
    {
      /* The offset of the data bytes is the offset of the
         parameter bytes plus the number of parameters being sent this time */
      SSVAL(outbuf,smb_droff,((smb_buf(outbuf)+alignment_offset) - 
            smb_base(outbuf)) + params_sent_thistime + data_alignment_offset);
      SSVAL(outbuf,smb_drdisp, pd - pdata);
    }

    /* Copy the param bytes into the packet */
    if(params_sent_thistime)
      memcpy((smb_buf(outbuf)+alignment_offset),pp,params_sent_thistime);
    /* Copy in the data bytes */
    if(data_sent_thistime)
      memcpy(smb_buf(outbuf)+alignment_offset+params_sent_thistime+
             data_alignment_offset,pd,data_sent_thistime);

    DEBUG(9,("t2_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
          params_sent_thistime, data_sent_thistime, useable_space));
    DEBUG(9,("t2_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
          params_to_send, data_to_send, paramsize, datasize));

    /* Send the packet */
    if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("send_trans2_replies: send_smb failed.");

    pp += params_sent_thistime;
    pd += data_sent_thistime;

    params_to_send -= params_sent_thistime;
    data_to_send -= data_sent_thistime;

    /* Sanity check */
    if(params_to_send < 0 || data_to_send < 0)
    {
      DEBUG(0,("send_trans2_replies failed sanity check pts = %d, dts = %d\n!!!",
            params_to_send, data_to_send));
      return -1;
    }
  }

  return 0;
}

/****************************************************************************
 Reply to a TRANSACT2_OPEN.
****************************************************************************/

static int call_trans2open(connection_struct *conn, char *inbuf, char *outbuf, 
			   int bufsize,  
			   char **pparams, char **ppdata)
{
  char *params = *pparams;
  int16 open_mode = SVAL(params, 2);
  int16 open_attr = SVAL(params,6);
  BOOL oplock_request = (((SVAL(params,0)|(1<<1))>>1) | ((SVAL(params,0)|(1<<2))>>1));
#if 0
  BOOL return_additional_info = BITSETW(params,0);
  int16 open_sattr = SVAL(params, 4);
  time_t open_time = make_unix_date3(params+8);
#endif
  int16 open_ofun = SVAL(params,12);
  int32 open_size = IVAL(params,14);
  char *pname = &params[28];
  pstring fname;
  mode_t unixmode;
  SMB_OFF_T size=0;
  int fmode=0,mtime=0,rmode;
  SMB_INO_T inode = 0;
  SMB_STRUCT_STAT sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;

  srvstr_pull(inbuf, fname, pname, sizeof(fname), -1, STR_TERMINATE);

  DEBUG(3,("trans2open %s mode=%d attr=%d ofun=%d size=%d\n",
	   fname,open_mode, open_attr, open_ofun, open_size));

  if (IS_IPC(conn)) {
		return(ERROR_DOS(ERRSRV,ERRaccess));
  }

  /* XXXX we need to handle passed times, sattr and flags */

  unix_convert(fname,conn,0,&bad_path,&sbuf);
    
  if (!check_name(fname,conn))
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  unixmode = unix_mode(conn,open_attr | aARCH, fname);
      
  fsp = open_file_shared(conn,fname,&sbuf,open_mode,open_ofun,unixmode,
		   oplock_request, &rmode,&smb_action);
      
  if (!fsp)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  size = sbuf.st_size;
  fmode = dos_mode(conn,fname,&sbuf);
  mtime = sbuf.st_mtime;
  inode = sbuf.st_ino;
  if (fmode & aDIR) {
    close_file(fsp,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }

  /* Realloc the size of parameters and data we will return */
  params	= Realloc(*pparams, 28);
  if( params == NULL ) {
    return(ERROR_DOS(ERRDOS,ERRnomem));
  }
  *pparams	= params;

  memset((char *)params,'\0',28);
  SSVAL(params,0,fsp->fnum);
  SSVAL(params,2,fmode);
  put_dos_date2(params,4, mtime);
  SIVAL(params,8, (uint32)size);
  SSVAL(params,12,rmode);

  if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  SSVAL(params,18,smb_action);
  /*
   * WARNING - this may need to be changed if SMB_INO_T <> 4 bytes.
   */
  SIVAL(params,20,inode);
 
  /* Send the required number of replies */
  send_trans2_replies(outbuf, bufsize, params, 28, *ppdata, 0);

  return -1;
}

/*********************************************************
 Routine to check if a given string matches exactly.
 as a special case a mask of "." does NOT match. That
 is required for correct wildcard semantics
 Case can be significant or not.
**********************************************************/

static BOOL exact_match(char *str,char *mask, BOOL case_sig) 
{
	if (mask[0] == '.' && mask[1] == 0)
		return False;
	if (case_sig)	
		return strcmp(str,mask)==0;
	return strcasecmp(str,mask) == 0;
}

/****************************************************************************
 Get a level dependent lanman2 dir entry.
****************************************************************************/

static BOOL get_lanman2_dir_entry(connection_struct *conn,
				  void *inbuf, void *outbuf,
				 char *path_mask,int dirtype,int info_level,
				 int requires_resume_key,
				 BOOL dont_descend,char **ppdata, 
				 char *base_data, int space_remaining, 
				 BOOL *out_of_space, BOOL *got_exact_match,
				 int *last_name_off)
{
	char *dname;
	BOOL found = False;
	SMB_STRUCT_STAT sbuf;
	pstring mask;
	pstring pathreal;
	pstring fname;
	char *p, *q, *pdata = *ppdata;
	uint32 reskey=0;
	int prev_dirpos=0;
	int mode=0;
	SMB_OFF_T size = 0;
	SMB_OFF_T allocation_size = 0;
	uint32 len;
	time_t mdate=0, adate=0, cdate=0;
	char *nameptr;
	BOOL was_8_3;
	int nt_extmode; /* Used for NT connections instead of mode */
	BOOL needslash = ( conn->dirpath[strlen(conn->dirpath) -1] != '/');

	*fname = 0;
	*out_of_space = False;
	*got_exact_match = False;

	if (!conn->dirptr)
		return(False);

	p = strrchr_m(path_mask,'/');
	if(p != NULL) {
		if(p[1] == '\0')
			pstrcpy(mask,"*.*");
		else
			pstrcpy(mask, p+1);
	} else
		pstrcpy(mask, path_mask);

	while (!found) {
		BOOL got_match;

		/* Needed if we run out of space */
		prev_dirpos = TellDir(conn->dirptr);
		dname = ReadDirName(conn->dirptr);

		/*
		 * Due to bugs in NT client redirectors we are not using
		 * resume keys any more - set them to zero.
		 * Check out the related comments in findfirst/findnext.
		 * JRA.
		 */

		reskey = 0;

		DEBUG(8,("get_lanman2_dir_entry:readdir on dirptr 0x%lx now at offset %d\n",
			(long)conn->dirptr,TellDir(conn->dirptr)));
      
		if (!dname) 
			return(False);

		pstrcpy(fname,dname);      

		if(!(got_match = *got_exact_match = exact_match(fname, mask, case_sensitive)))
			got_match = mask_match(fname, mask, case_sensitive);

		if(!got_match && !is_8_3(fname, False)) {

			/*
			 * It turns out that NT matches wildcards against
			 * both long *and* short names. This may explain some
			 * of the wildcard wierdness from old DOS clients
			 * that some people have been seeing.... JRA.
			 */

			pstring newname;
			pstrcpy( newname, fname);
			name_map_mangle( newname, True, False, SNUM(conn));
			if(!(got_match = *got_exact_match = exact_match(newname, mask, case_sensitive)))
				got_match = mask_match(newname, mask, case_sensitive);
		}

		if(got_match) {
			BOOL isdots = (strequal(fname,"..") || strequal(fname,"."));
			if (dont_descend && !isdots)
				continue;
	  
			pstrcpy(pathreal,conn->dirpath);
			if(needslash)
				pstrcat(pathreal,"/");
			pstrcat(pathreal,dname);

			if (vfs_stat(conn,pathreal,&sbuf) != 0) {
				/* Needed to show the msdfs symlinks as directories */
				if(!lp_host_msdfs() || !lp_msdfs_root(SNUM(conn)) 
						|| !is_msdfs_link(conn, pathreal)) {
					DEBUG(5,("get_lanman2_dir_entry:Couldn't stat [%s] (%s)\n",
							pathreal,strerror(errno)));
					continue;
				} else {
					DEBUG(5,("get_lanman2_dir_entry: Masquerading msdfs link %s as a directory\n",
							pathreal));
					sbuf.st_mode = (sbuf.st_mode & 0xFFF) | S_IFDIR;
				}
			}

			mode = dos_mode(conn,pathreal,&sbuf);

			if (!dir_check_ftype(conn,mode,&sbuf,dirtype)) {
				DEBUG(5,("[%s] attribs didn't match %x\n",fname,dirtype));
				continue;
			}

			size = sbuf.st_size;
			allocation_size = SMB_ROUNDUP_ALLOCATION(sbuf.st_size);
			mdate = sbuf.st_mtime;
			adate = sbuf.st_atime;
			cdate = get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn)));

			if (lp_dos_filetime_resolution(SNUM(conn))) {
				cdate &= ~1;
				mdate &= ~1;
				adate &= ~1;
			}

			if(mode & aDIR)
				size = 0;

			DEBUG(5,("get_lanman2_dir_entry found %s fname=%s\n",pathreal,fname));
	  
			found = True;
		}
	}

	name_map_mangle(fname,False,True,SNUM(conn));

	p = pdata;
	nameptr = p;

	nt_extmode = mode ? mode : FILE_ATTRIBUTE_NORMAL;

	switch (info_level) {
		case 1:
			if(requires_resume_key) {
				SIVAL(p,0,reskey);
				p += 4;
			}
			put_dos_date2(p,l1_fdateCreation,cdate);
			put_dos_date2(p,l1_fdateLastAccess,adate);
			put_dos_date2(p,l1_fdateLastWrite,mdate);
			SIVAL(p,l1_cbFile,(uint32)size);
			SIVAL(p,l1_cbFileAlloc,(uint32)allocation_size);
			SSVAL(p,l1_attrFile,mode);
			p += l1_achName;
			nameptr = p;
			p += align_string(outbuf, p, 0);
			len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
			SCVAL(nameptr, -1, len);
			p += len;
			break;

		case 2:
			if(requires_resume_key) {
				SIVAL(p,0,reskey);
				p += 4;
			}
			put_dos_date2(p,l2_fdateCreation,cdate);
			put_dos_date2(p,l2_fdateLastAccess,adate);
			put_dos_date2(p,l2_fdateLastWrite,mdate);
			SIVAL(p,l2_cbFile,(uint32)size);
			SIVAL(p,l2_cbFileAlloc,(uint32)allocation_size);
			SSVAL(p,l2_attrFile,mode);
			SIVAL(p,l2_cbList,0); /* No extended attributes */
			p += l2_achName;
			nameptr = p;
			len = srvstr_push(outbuf, p, fname, -1, STR_NOALIGN);
			SCVAL(p, -1, len);
			p += len;
			*p++ = 0; /* craig from unisys pointed out we need this */
			break;

		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
			was_8_3 = is_8_3(fname, True);
			p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size);
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			q = p; p += 4;
			SIVAL(p,0,0); p += 4;
			if (!was_8_3) {
				pstring mangled_name;
				pstrcpy(mangled_name, fname);
				name_map_mangle(mangled_name,True,True,SNUM(conn));
				mangled_name[12] = 0;
				len = srvstr_push(outbuf, p+2, mangled_name, 24, STR_UPPER);
				SSVAL(p, 0, len);
			} else {
				SSVAL(p,0,0);
				*(p+2) = 0;
			}
			p += 2 + 24;
			len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
			SIVAL(q,0,len);
			p += len;
			len = PTR_DIFF(p, pdata);
			len = (len + 3) & ~3;
			SIVAL(pdata,0,len);
			p = pdata + len;
			break;

		case SMB_FIND_FILE_DIRECTORY_INFO:
			p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size);
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			p += 4;
			len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
			SIVAL(p, -4, len);
			p += len;
			len = PTR_DIFF(p, pdata);
			len = (len + 3) & ~3;
			SIVAL(pdata,0,len);
			p = pdata + len;
			break;
      
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
			p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size); 
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			p += 4;
			SIVAL(p,0,0); p += 4;

			len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
			SIVAL(p, -4, len);
			p += len;

			len = PTR_DIFF(p, pdata);
			len = (len + 3) & ~3;
			SIVAL(pdata,0,len);
			p = pdata + len;
			break;

		case SMB_FIND_FILE_NAMES_INFO:
			p += 4;
			SIVAL(p,0,reskey); p += 4;
			p += 4;
			len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
			SIVAL(p, -4, len);
			p += len;
			len = PTR_DIFF(p, pdata);
			len = (len + 3) & ~3;
			SIVAL(pdata,0,len);
			p = pdata + len;
			break;

		default:      
			return(False);
	}


	if (PTR_DIFF(p,pdata) > space_remaining) {
		/* Move the dirptr back to prev_dirpos */
		SeekDir(conn->dirptr, prev_dirpos);
		*out_of_space = True;
		DEBUG(9,("get_lanman2_dir_entry: out of space\n"));
		return False; /* Not finished - just out of space */
	}

	/* Setup the last_filename pointer, as an offset from base_data */
	*last_name_off = PTR_DIFF(nameptr,base_data);
	/* Advance the data pointer to the next slot */
	*ppdata = p;

	return(found);
}

/****************************************************************************
 Reply to a TRANS2_FINDFIRST.
****************************************************************************/

static int call_trans2findfirst(connection_struct *conn,
				char *inbuf, char *outbuf, int bufsize,  
				char **pparams, char **ppdata)
{
  /* We must be careful here that we don't return more than the
     allowed number of data bytes. If this means returning fewer than
     maxentries then so be it. We assume that the redirector has
     enough room for the fixed number of parameter bytes it has
     requested. */
  uint32 max_data_bytes = SVAL(inbuf, smb_mdrcnt);
  char *params = *pparams;
  char *pdata = *ppdata;
  int dirtype = SVAL(params,0);
  int maxentries = SVAL(params,2);
  BOOL close_after_first = BITSETW(params+4,0);
  BOOL close_if_end = BITSETW(params+4,1);
  BOOL requires_resume_key = BITSETW(params+4,2);
  int info_level = SVAL(params,6);
  pstring directory;
  pstring mask;
  char *p, *wcard;
  int last_name_off=0;
  int dptr_num = -1;
  int numentries = 0;
  int i;
  BOOL finished = False;
  BOOL dont_descend = False;
  BOOL out_of_space = False;
  int space_remaining;
  BOOL bad_path = False;
  SMB_STRUCT_STAT sbuf;

  *directory = *mask = 0;

  DEBUG(3,("call_trans2findfirst: dirtype = %d, maxentries = %d, close_after_first=%d, close_if_end = %d requires_resume_key = %d level = %d, max_data_bytes = %d\n",
	   dirtype, maxentries, close_after_first, close_if_end, requires_resume_key,
	   info_level, max_data_bytes));
  
  switch (info_level) 
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case SMB_FIND_FILE_DIRECTORY_INFO:
    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
    case SMB_FIND_FILE_NAMES_INFO:
    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
      break;
    default:
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }

  srvstr_pull(inbuf, directory, params+12, sizeof(directory), -1, STR_TERMINATE);

  RESOLVE_FINDFIRST_DFSPATH(directory, conn, inbuf, outbuf);

  unix_convert(directory,conn,0,&bad_path,&sbuf);
  if(!check_name(directory,conn)) {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }

#if 0
    /* Ugly - NT specific hack - maybe not needed ? (JRA) */
    if((errno == ENOTDIR) && (Protocol >= PROTOCOL_NT1) && 
       (get_remote_arch() == RA_WINNT))
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbaddirectory;
    }
#endif 

    return(UNIXERROR(ERRDOS,ERRbadpath));
  }

  p = strrchr_m(directory,'/');
  if(p == NULL) {
    pstrcpy(mask,directory);
    pstrcpy(directory,"./");
  } else {
    pstrcpy(mask,p+1);
    *p = 0;
  }

  DEBUG(5,("dir=%s, mask = %s\n",directory, mask));

  pdata	= Realloc(*ppdata, max_data_bytes + 1024);
  if( pdata == NULL ) {
    return(ERROR_DOS(ERRDOS,ERRnomem));
  }
  *ppdata	= pdata;
  memset((char *)pdata,'\0',max_data_bytes + 1024);

  /* Realloc the params space */
  params = Realloc(*pparams, 10);
  if (params == NULL) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *pparams	= params;

  dptr_num = dptr_create(conn,directory, False, True ,SVAL(inbuf,smb_pid));
  if (dptr_num < 0)
    return(UNIXERROR(ERRDOS,ERRbadfile));

  /* Save the wildcard match and attribs we are using on this directory - 
     needed as lanman2 assumes these are being saved between calls */

  if(!(wcard = strdup(mask))) {
    dptr_close(&dptr_num);
    return ERROR_DOS(ERRDOS,ERRnomem);
  }

  dptr_set_wcard(dptr_num, wcard);
  dptr_set_attr(dptr_num, dirtype);

  DEBUG(4,("dptr_num is %d, wcard = %s, attr = %d\n",dptr_num, wcard, dirtype));

  /* We don't need to check for VOL here as this is returned by 
     a different TRANS2 call. */
  
  DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
	   conn->dirpath,lp_dontdescend(SNUM(conn))));
  if (in_list(conn->dirpath,lp_dontdescend(SNUM(conn)),case_sensitive))
    dont_descend = True;
    
  p = pdata;
  space_remaining = max_data_bytes;
  out_of_space = False;

  for (i=0;(i<maxentries) && !finished && !out_of_space;i++)
  {
    BOOL got_exact_match = False;

    /* this is a heuristic to avoid seeking the dirptr except when 
       absolutely necessary. It allows for a filename of about 40 chars */
    if (space_remaining < DIRLEN_GUESS && numentries > 0)
    {
      out_of_space = True;
      finished = False;
    }
    else
    {
      finished = !get_lanman2_dir_entry(conn,
					inbuf, outbuf,
					mask,dirtype,info_level,
					requires_resume_key,dont_descend,
					&p,pdata,space_remaining, &out_of_space, &got_exact_match,
					&last_name_off);
    }

    if (finished && out_of_space)
      finished = False;

    if (!finished && !out_of_space)
      numentries++;

    /*
     * As an optimisation if we know we aren't looking
     * for a wildcard name (ie. the name matches the wildcard exactly)
     * then we can finish on any (first) match.
     * This speeds up large directory searches. JRA.
     */

    if(got_exact_match)
      finished = True;

    space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
  }
  
  /* Check if we can close the dirptr */
  if(close_after_first || (finished && close_if_end))
  {
    DEBUG(5,("call_trans2findfirst - (2) closing dptr_num %d\n", dptr_num));
    dptr_close(&dptr_num);
  }

  /* 
   * If there are no matching entries we must return ERRDOS/ERRbadfile - 
   * from observation of NT.
   */

  if(numentries == 0) {
	  dptr_close(&dptr_num);
	  return ERROR_DOS(ERRDOS,ERRbadfile);
  }

  /* At this point pdata points to numentries directory entries. */

  /* Set up the return parameter block */
  SSVAL(params,0,dptr_num);
  SSVAL(params,2,numentries);
  SSVAL(params,4,finished);
  SSVAL(params,6,0); /* Never an EA error */
  SSVAL(params,8,last_name_off);

  send_trans2_replies( outbuf, bufsize, params, 10, pdata, PTR_DIFF(p,pdata));

  if ((! *directory) && dptr_path(dptr_num))
    slprintf(directory,sizeof(directory)-1, "(%s)",dptr_path(dptr_num));

  DEBUG( 4, ( "%s mask=%s directory=%s dirtype=%d numentries=%d\n",
	    smb_fn_name(CVAL(inbuf,smb_com)), 
	    mask, directory, dirtype, numentries ) );

  /* 
   * Force a name mangle here to ensure that the
   * mask as an 8.3 name is top of the mangled cache.
   * The reasons for this are subtle. Don't remove
   * this code unless you know what you are doing
   * (see PR#13758). JRA.
   */

  if(!is_8_3( mask, False))
    name_map_mangle(mask, True, True, SNUM(conn));

  return(-1);
}

/****************************************************************************
 Reply to a TRANS2_FINDNEXT.
****************************************************************************/

static int call_trans2findnext(connection_struct *conn, 
			       char *inbuf, char *outbuf, 
			       int length, int bufsize,
			       char **pparams, char **ppdata)
{
  /* We must be careful here that we don't return more than the
     allowed number of data bytes. If this means returning fewer than
     maxentries then so be it. We assume that the redirector has
     enough room for the fixed number of parameter bytes it has
     requested. */
  int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
  char *params = *pparams;
  char *pdata = *ppdata;
  int dptr_num = SVAL(params,0);
  int maxentries = SVAL(params,2);
  uint16 info_level = SVAL(params,4);
  uint32 resume_key = IVAL(params,6);
  BOOL close_after_request = BITSETW(params+10,0);
  BOOL close_if_end = BITSETW(params+10,1);
  BOOL requires_resume_key = BITSETW(params+10,2);
  BOOL continue_bit = BITSETW(params+10,3);
  pstring resume_name;
  pstring mask;
  pstring directory;
  char *p;
  uint16 dirtype;
  int numentries = 0;
  int i, last_name_off=0;
  BOOL finished = False;
  BOOL dont_descend = False;
  BOOL out_of_space = False;
  int space_remaining;

  *mask = *directory = *resume_name = 0;

  srvstr_pull(inbuf, resume_name, params+12, sizeof(resume_name), -1, STR_TERMINATE);

  DEBUG(3,("call_trans2findnext: dirhandle = %d, max_data_bytes = %d, maxentries = %d, \
close_after_request=%d, close_if_end = %d requires_resume_key = %d \
resume_key = %d resume name = %s continue=%d level = %d\n",
	   dptr_num, max_data_bytes, maxentries, close_after_request, close_if_end, 
	   requires_resume_key, resume_key, resume_name, continue_bit, info_level));

  switch (info_level) 
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case SMB_FIND_FILE_DIRECTORY_INFO:
    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
    case SMB_FIND_FILE_NAMES_INFO:
    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
      break;
    default:
      return ERROR_DOS(ERRDOS,ERRunknownlevel);
    }

  pdata = Realloc( *ppdata, max_data_bytes + 1024);
  if(pdata == NULL) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *ppdata	= pdata;
  memset((char *)pdata,'\0',max_data_bytes + 1024);

  /* Realloc the params space */
  params = Realloc(*pparams, 6*SIZEOFWORD);
  if( params == NULL ) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *pparams	= params;

  /* Check that the dptr is valid */
  if(!(conn->dirptr = dptr_fetch_lanman2(dptr_num)))
    return ERROR_DOS(ERRDOS,ERRnofiles);

  string_set(&conn->dirpath,dptr_path(dptr_num));

  /* Get the wildcard mask from the dptr */
  if((p = dptr_wcard(dptr_num))== NULL) {
    DEBUG(2,("dptr_num %d has no wildcard\n", dptr_num));
    return ERROR_DOS(ERRDOS,ERRnofiles);
  }
  pstrcpy(mask, p);
  pstrcpy(directory,conn->dirpath);

  /* Get the attr mask from the dptr */
  dirtype = dptr_attr(dptr_num);

  DEBUG(3,("dptr_num is %d, mask = %s, attr = %x, dirptr=(0x%lX,%d)\n",
	   dptr_num, mask, dirtype, 
	   (long)conn->dirptr,
	   TellDir(conn->dirptr)));

  /* We don't need to check for VOL here as this is returned by 
     a different TRANS2 call. */

  DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",conn->dirpath,lp_dontdescend(SNUM(conn))));
  if (in_list(conn->dirpath,lp_dontdescend(SNUM(conn)),case_sensitive))
    dont_descend = True;
    
  p = pdata;
  space_remaining = max_data_bytes;
  out_of_space = False;

  /* 
   * Seek to the correct position. We no longer use the resume key but
   * depend on the last file name instead.
   */
  if(requires_resume_key && *resume_name && !continue_bit)
  {
    /*
     * Fix for NT redirector problem triggered by resume key indexes
     * changing between directory scans. We now return a resume key of 0
     * and instead look for the filename to continue from (also given
     * to us by NT/95/smbfs/smbclient). If no other scans have been done between the
     * findfirst/findnext (as is usual) then the directory pointer
     * should already be at the correct place. Check this by scanning
     * backwards looking for an exact (ie. case sensitive) filename match. 
     * If we get to the beginning of the directory and haven't found it then scan
     * forwards again looking for a match. JRA.
     */

    int current_pos, start_pos;
    char *dname = NULL;
    void *dirptr = conn->dirptr;
    start_pos = TellDir(dirptr);
    for(current_pos = start_pos; current_pos >= 0; current_pos--)
    {
      DEBUG(7,("call_trans2findnext: seeking to pos %d\n", current_pos));

      SeekDir(dirptr, current_pos);
      dname = ReadDirName(dirptr);

      /*
       * Remember, name_map_mangle is called by
       * get_lanman2_dir_entry(), so the resume name
       * could be mangled. Ensure we do the same
       * here.
       */

      if(dname != NULL)
        name_map_mangle( dname, False, True, SNUM(conn));

      if(dname && strcsequal( resume_name, dname))
      {
        SeekDir(dirptr, current_pos+1);
        DEBUG(7,("call_trans2findnext: got match at pos %d\n", current_pos+1 ));
        break;
      }
    }

    /*
     * Scan forward from start if not found going backwards.
     */

    if(current_pos < 0)
    {
      DEBUG(7,("call_trans2findnext: notfound: seeking to pos %d\n", start_pos));
      SeekDir(dirptr, start_pos);
      for(current_pos = start_pos; (dname = ReadDirName(dirptr)) != NULL; SeekDir(dirptr,++current_pos))
      {
        /*
         * Remember, name_map_mangle is called by
         * get_lanman2_dir_entry(), so the resume name
         * could be mangled. Ensure we do the same
         * here.
         */

        if(dname != NULL)
          name_map_mangle( dname, False, True, SNUM(conn));

        if(dname && strcsequal( resume_name, dname))
        {
          SeekDir(dirptr, current_pos+1);
          DEBUG(7,("call_trans2findnext: got match at pos %d\n", current_pos+1 ));
          break;
        }
      } /* end for */
    } /* end if current_pos */
  } /* end if requires_resume_key && !continue_bit */

  for (i=0;(i<(int)maxentries) && !finished && !out_of_space ;i++)
  {
    BOOL got_exact_match = False;

    /* this is a heuristic to avoid seeking the dirptr except when 
       absolutely necessary. It allows for a filename of about 40 chars */
    if (space_remaining < DIRLEN_GUESS && numentries > 0)
    {
      out_of_space = True;
      finished = False;
    }
    else
    {
      finished = !get_lanman2_dir_entry(conn,
					inbuf, outbuf,
					mask,dirtype,info_level,
					requires_resume_key,dont_descend,
					&p,pdata,space_remaining, &out_of_space, &got_exact_match,
					&last_name_off);
    }

    if (finished && out_of_space)
      finished = False;

    if (!finished && !out_of_space)
      numentries++;

    /*
     * As an optimisation if we know we aren't looking
     * for a wildcard name (ie. the name matches the wildcard exactly)
     * then we can finish on any (first) match.
     * This speeds up large directory searches. JRA.
     */

    if(got_exact_match)
      finished = True;

    space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
  }
  
  /* Check if we can close the dirptr */
  if(close_after_request || (finished && close_if_end))
  {
    DEBUG(5,("call_trans2findnext: closing dptr_num = %d\n", dptr_num));
    dptr_close(&dptr_num); /* This frees up the saved mask */
  }


  /* Set up the return parameter block */
  SSVAL(params,0,numentries);
  SSVAL(params,2,finished);
  SSVAL(params,4,0); /* Never an EA error */
  SSVAL(params,6,last_name_off);

  send_trans2_replies( outbuf, bufsize, params, 8, pdata, PTR_DIFF(p,pdata));

  if ((! *directory) && dptr_path(dptr_num))
    slprintf(directory,sizeof(directory)-1, "(%s)",dptr_path(dptr_num));

  DEBUG( 3, ( "%s mask=%s directory=%s dirtype=%d numentries=%d\n",
	    smb_fn_name(CVAL(inbuf,smb_com)), 
	    mask, directory, dirtype, numentries ) );

  return(-1);
}

/****************************************************************************
 Reply to a TRANS2_QFSINFO (query filesystem info).
****************************************************************************/

static int call_trans2qfsinfo(connection_struct *conn, 
			      char *inbuf, char *outbuf, 
			      int length, int bufsize,
			      char **pparams, char **ppdata)
{
  int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
  char *pdata = *ppdata;
  char *params = *pparams;
  uint16 info_level = SVAL(params,0);
  int data_len, len;
  SMB_STRUCT_STAT st;
  char *vname = volume_label(SNUM(conn));
  int snum = SNUM(conn);
  char *fstype = lp_fstype(SNUM(conn));

  DEBUG(3,("call_trans2qfsinfo: level = %d\n", info_level));

  if(vfs_stat(conn,".",&st)!=0) {
    DEBUG(2,("call_trans2qfsinfo: stat of . failed (%s)\n", strerror(errno)));
    return ERROR_DOS(ERRSRV,ERRinvdevice);
  }

  pdata = Realloc(*ppdata, max_data_bytes + 1024);
  if ( pdata == NULL ) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *ppdata	= pdata;
  memset((char *)pdata,'\0',max_data_bytes + 1024);

  switch (info_level) 
  {
    case 1:
    {
      SMB_BIG_UINT dfree,dsize,bsize;
      data_len = 18;
      conn->vfs_ops.disk_free(conn,".",False,&bsize,&dfree,&dsize);	
      SIVAL(pdata,l1_idFileSystem,st.st_dev);
      SIVAL(pdata,l1_cSectorUnit,bsize/512);
      SIVAL(pdata,l1_cUnit,dsize);
      SIVAL(pdata,l1_cUnitAvail,dfree);
      SSVAL(pdata,l1_cbSector,512);
      DEBUG(5,("call_trans2qfsinfo : bsize=%u, id=%x, cSectorUnit=%u, cUnit=%u, cUnitAvail=%u, cbSector=%d\n",
		 (unsigned int)bsize, (unsigned int)st.st_dev, ((unsigned int)bsize)/512, (unsigned int)dsize,
         (unsigned int)dfree, 512));
      break;
    }
    case 2:
	    /* Return volume name */
	    /* 
	     * Add volume serial number - hash of a combination of
	     * the called hostname and the service name.
	     */
	    SIVAL(pdata,0,str_checksum(lp_servicename(snum)) ^ (str_checksum(local_machine)<<16) );
	    len = srvstr_push(outbuf, pdata+l2_vol_szVolLabel, vname, -1, 
			      STR_TERMINATE);
	    SCVAL(pdata,l2_vol_cch,len);
	    data_len = l2_vol_szVolLabel + len;
	    DEBUG(5,("call_trans2qfsinfo : time = %x, namelen = %d, name = %s\n",
		     (unsigned)st.st_ctime, len, vname));
	    break;

    case SMB_QUERY_FS_ATTRIBUTE_INFO:
	    SIVAL(pdata,0,FILE_CASE_PRESERVED_NAMES|FILE_CASE_SENSITIVE_SEARCH|
		  (lp_nt_acl_support(SNUM(conn)) ? FILE_PERSISTENT_ACLS : 0)); /* FS ATTRIBUTES */
	    SIVAL(pdata,4,255); /* Max filename component length */
	    /* NOTE! the fstype must *not* be null terminated or win98 won't recognise it
	       and will think we can't do long filenames */
	    len = srvstr_push(outbuf, pdata+12, fstype, -1, 0);
	    SIVAL(pdata,8,len);
	    data_len = 12 + len;
	    break;

    case SMB_QUERY_FS_LABEL_INFO:
	    len = srvstr_push(outbuf, pdata+4, vname, -1, STR_TERMINATE);
	    data_len = 4 + len;
	    SIVAL(pdata,0,len);
	    break;
    case SMB_QUERY_FS_VOLUME_INFO:      
	    /* 
	     * Add volume serial number - hash of a combination of
	     * the called hostname and the service name.
	     */
	    SIVAL(pdata,8,str_checksum(lp_servicename(snum)) ^ 
		  (str_checksum(local_machine)<<16));

	    len = srvstr_push(outbuf, pdata+18, vname, -1, STR_TERMINATE);
	    SIVAL(pdata,12,len);
	    data_len = 18+len;
	    DEBUG(5,("call_trans2qfsinfo : SMB_QUERY_FS_VOLUME_INFO namelen = %d, vol=%s serv=%s\n", 
		     (int)strlen(vname),vname, lp_servicename(snum)));
	    break;
    case SMB_QUERY_FS_SIZE_INFO:
    {
      SMB_BIG_UINT dfree,dsize,bsize;
      data_len = 24;
      conn->vfs_ops.disk_free(conn,".",False,&bsize,&dfree,&dsize);	
      SBIG_UINT(pdata,0,dsize);
      SBIG_UINT(pdata,8,dfree);
      SIVAL(pdata,16,bsize/512);
      SIVAL(pdata,20,512);
      break;
    }
    case SMB_QUERY_FS_DEVICE_INFO:
      data_len = 8;
      SIVAL(pdata,0,0); /* dev type */
      SIVAL(pdata,4,0); /* characteristics */
      break;
    case SMB_MAC_QUERY_FS_INFO:
	    /*
	     * Thursby MAC extension... ONLY on NTFS filesystems
	     * once we do streams then we don't need this
	     */
	    if (strequal(lp_fstype(SNUM(conn)),"NTFS")) {
		    data_len = 88;
		    SIVAL(pdata,84,0x100); /* Don't support mac... */
		    break;
	    }
	    /* drop through */
  default:
	  return ERROR_DOS(ERRDOS,ERRunknownlevel);
  }


  send_trans2_replies( outbuf, bufsize, params, 0, pdata, data_len);

  DEBUG( 4, ( "%s info_level = %d\n",
            smb_fn_name(CVAL(inbuf,smb_com)), info_level) );

  return -1;
}

/****************************************************************************
 Reply to a TRANS2_SETFSINFO (set filesystem info).
****************************************************************************/

static int call_trans2setfsinfo(connection_struct *conn,
				char *inbuf, char *outbuf, int length, 
				int bufsize,
				char **pparams, char **ppdata)
{
  /* Just say yes we did it - there is nothing that
     can be set here so it doesn't matter. */
  int outsize;
  DEBUG(3,("call_trans2setfsinfo\n"));

  if (!CAN_WRITE(conn))
    return ERROR_DOS(ERRSRV,ERRaccess);

  outsize = set_message(outbuf,10,0,True);

  return outsize;
}

/****************************************************************************
 Reply to a TRANS2_QFILEPATHINFO or TRANSACT2_QFILEINFO (query file info by
 file name or file id).
****************************************************************************/

static int call_trans2qfilepathinfo(connection_struct *conn,
				    char *inbuf, char *outbuf, int length, 
				    int bufsize,
				    char **pparams,char **ppdata,
				    int total_data)
{
	int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
	char *params = *pparams;
	char *pdata = *ppdata;
	uint16 tran_call = SVAL(inbuf, smb_setup0);
	uint16 info_level;
	int mode=0;
	SMB_OFF_T size=0;
	SMB_OFF_T allocation_size=0;
	unsigned int data_size;
	SMB_STRUCT_STAT sbuf;
	pstring fname;
	char *base_name;
	char *p;
	SMB_OFF_T pos = 0;
	BOOL bad_path = False;
	BOOL delete_pending = False;
	int len;
	time_t c_time;

	if (tran_call == TRANSACT2_QFILEINFO) {
		files_struct *fsp = file_fsp(params,0);
		info_level = SVAL(params,2);

		DEBUG(3,("call_trans2qfilepathinfo: TRANSACT2_QFILEINFO: level = %d\n", info_level));

		if(fsp && (fsp->is_directory || fsp->stat_open)) {
			/*
			 * This is actually a QFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			pstrcpy(fname, fsp->fsp_name);
			unix_convert(fname,conn,0,&bad_path,&sbuf);
			if (!check_name(fname,conn) || 
					(!VALID_STAT(sbuf) && vfs_stat(conn,fname,&sbuf))) {
				DEBUG(3,("fileinfo of %s failed (%s)\n",fname,strerror(errno)));
				if((errno == ENOENT) && bad_path) {
					unix_ERR_class = ERRDOS;
					unix_ERR_code = ERRbadpath;
				}
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}
		  
			delete_pending = fsp->directory_delete_on_close;
		} else {
			/*
			 * Original code - this is an open file.
			 */
			CHECK_FSP(fsp,conn);

			pstrcpy(fname, fsp->fsp_name);
			if (vfs_fstat(fsp,fsp->fd,&sbuf) != 0) {
				DEBUG(3,("fstat of fnum %d failed (%s)\n", fsp->fnum, strerror(errno)));
				return(UNIXERROR(ERRDOS,ERRbadfid));
			}
			if((pos = fsp->conn->vfs_ops.lseek(fsp,fsp->fd,0,SEEK_CUR)) == -1)
				return(UNIXERROR(ERRDOS,ERRnoaccess));

			delete_pending = fsp->delete_on_close;
		}
	} else {
		/* qpathinfo */
		info_level = SVAL(params,0);

		DEBUG(3,("call_trans2qfilepathinfo: TRANSACT2_QPATHINFO: level = %d\n", info_level));

		srvstr_pull(inbuf, fname, &params[6], sizeof(fname), -1, STR_TERMINATE);

		RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

		unix_convert(fname,conn,0,&bad_path,&sbuf);
		if (!check_name(fname,conn) || 
				(!VALID_STAT(sbuf) && vfs_stat(conn,fname,&sbuf))) {
			DEBUG(3,("fileinfo of %s failed (%s)\n",fname,strerror(errno)));
			if((errno == ENOENT) && bad_path) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}
	}


	DEBUG(3,("call_trans2qfilepathinfo %s level=%d call=%d total_data=%d\n",
		fname,info_level,tran_call,total_data));

	p = strrchr_m(fname,'/'); 
	if (!p)
		base_name = fname;
	else
		base_name = p+1;

	mode = dos_mode(conn,fname,&sbuf);
	size = sbuf.st_size;
	allocation_size = SMB_ROUNDUP_ALLOCATION(sbuf.st_size);
	
	if (mode & aDIR)
		size = 0;

	params = Realloc(*pparams,2);
	if (params == NULL)
	  return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;
	memset((char *)params,'\0',2);
	data_size = max_data_bytes + 1024;
	pdata = Realloc(*ppdata, data_size); 
	if ( pdata == NULL )
		return ERROR_DOS(ERRDOS,ERRnomem);
	*ppdata = pdata;

	if (total_data > 0 && IVAL(pdata,0) == total_data) {
		/* uggh, EAs for OS2 */
		DEBUG(4,("Rejecting EA request with total_data=%d\n",total_data));
		return ERROR_DOS(ERRDOS,ERReasnotsupported);
	}

	memset((char *)pdata,'\0',data_size);

	c_time = get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn)));

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		c_time &= ~1;
		sbuf.st_atime &= ~1;
		sbuf.st_mtime &= ~1;
		sbuf.st_mtime &= ~1;
	}

	switch (info_level) {
		case SMB_INFO_STANDARD:
		case SMB_INFO_QUERY_EA_SIZE:
			data_size = (info_level==1?22:26);
			put_dos_date2(pdata,l1_fdateCreation,c_time);
			put_dos_date2(pdata,l1_fdateLastAccess,sbuf.st_atime);
			put_dos_date2(pdata,l1_fdateLastWrite,sbuf.st_mtime); /* write time */
			SIVAL(pdata,l1_cbFile,(uint32)size);
			SIVAL(pdata,l1_cbFileAlloc,(uint32)allocation_size);
			SSVAL(pdata,l1_attrFile,mode);
			SIVAL(pdata,l1_attrFile+2,4); /* this is what OS2 does */
			break;

		case SMB_INFO_QUERY_EAS_FROM_LIST:
			data_size = 24;
			put_dos_date2(pdata,0,c_time);
			put_dos_date2(pdata,4,sbuf.st_atime);
			put_dos_date2(pdata,8,sbuf.st_mtime);
			SIVAL(pdata,12,(uint32)size);
			SIVAL(pdata,16,(uint32)allocation_size);
			SIVAL(pdata,20,mode);
			break;

		case SMB_INFO_QUERY_ALL_EAS:
			data_size = 4;
			SIVAL(pdata,0,data_size);
			break;

		case 6:
			return ERROR_DOS(ERRDOS,ERRbadfunc); /* os/2 needs this */      

		case SMB_FILE_BASIC_INFORMATION:
		case SMB_QUERY_FILE_BASIC_INFO:

			if (info_level == SMB_QUERY_FILE_BASIC_INFO)
				data_size = 36; /* w95 returns 40 bytes not 36 - why ?. */
			else {
				data_size = 40;
				SIVAL(pdata,36,0);
			}
			put_long_date(pdata,c_time);
			put_long_date(pdata+8,sbuf.st_atime);
			put_long_date(pdata+16,sbuf.st_mtime); /* write time */
			put_long_date(pdata+24,sbuf.st_mtime); /* change time */
			SIVAL(pdata,32,mode);

			DEBUG(5,("SMB_QFBI - "));
			{
				time_t create_time = c_time;
				DEBUG(5,("create: %s ", ctime(&create_time)));
			}
			DEBUG(5,("access: %s ", ctime(&sbuf.st_atime)));
			DEBUG(5,("write: %s ", ctime(&sbuf.st_mtime)));
			DEBUG(5,("change: %s ", ctime(&sbuf.st_mtime)));
			DEBUG(5,("mode: %x\n", mode));

			break;

		case SMB_FILE_STANDARD_INFORMATION:
		case SMB_QUERY_FILE_STANDARD_INFO:
			data_size = 24;
			/* Fake up allocation size. */
			SOFF_T(pdata,0,allocation_size);
			SOFF_T(pdata,8,size);
			SIVAL(pdata,16,sbuf.st_nlink);
			CVAL(pdata,20) = 0;
			CVAL(pdata,21) = (mode&aDIR)?1:0;
			break;

		case SMB_FILE_EA_INFORMATION:
		case SMB_QUERY_FILE_EA_INFO:
			data_size = 4;
			break;

		/* Get the 8.3 name - used if NT SMB was negotiated. */
		case SMB_QUERY_FILE_ALT_NAME_INFO:
		{
			pstring short_name;

			pstrcpy(short_name,base_name);
			/* Mangle if not already 8.3 */
			if(!is_8_3(short_name, True)) {
				if(!name_map_mangle(short_name,True,True,SNUM(conn)))
					*short_name = '\0';
			}
			len = srvstr_push(outbuf, pdata+4, short_name, -1, STR_TERMINATE|STR_UPPER);
			data_size = 4 + len;
			SIVAL(pdata,0,len);
			break;
		}

		case SMB_QUERY_FILE_NAME_INFO:
			/*
			 * The first part of this code is essential
			 * to get security descriptors to work on mapped
			 * drives. Don't ask how I discovered this unless
			 * you like hearing about me suffering.... :-). JRA.
			 */
			if(strequal(".", fname)) {
				len = srvstr_push(outbuf, pdata+4, "\\", -1, STR_TERMINATE);
			} else {
				len = srvstr_push(outbuf, pdata+4, fname, -1, STR_TERMINATE);
			}
			data_size = 4 + len;
			SIVAL(pdata,0,len);
			break;

		case SMB_FILE_END_OF_FILE_INFORMATION:
		case SMB_QUERY_FILE_END_OF_FILEINFO:
			data_size = 8;
			SOFF_T(pdata,0,size);
			break;

		case SMB_FILE_ALLOCATION_INFORMATION:
		case SMB_QUERY_FILE_ALLOCATION_INFO:
			data_size = 8;
			SOFF_T(pdata,0,allocation_size);
			break;

		case SMB_QUERY_FILE_ALL_INFO:
			put_long_date(pdata,c_time);
			put_long_date(pdata+8,sbuf.st_atime);
			put_long_date(pdata+16,sbuf.st_mtime); /* write time */
			put_long_date(pdata+24,sbuf.st_mtime); /* change time */
			SIVAL(pdata,32,mode);
			pdata += 40;
			SOFF_T(pdata,0,allocation_size);
			SOFF_T(pdata,8,size);
			SIVAL(pdata,16,sbuf.st_nlink);
			CVAL(pdata,20) = delete_pending;
			CVAL(pdata,21) = (mode&aDIR)?1:0;
			pdata += 24;
			SINO_T(pdata,0,(SMB_INO_T)sbuf.st_ino); 
			pdata += 8; /* index number */
			pdata += 4; /* EA info */
			if (mode & aRONLY)
				SIVAL(pdata,0,0xA9);
			else
				SIVAL(pdata,0,0xd01BF);
			pdata += 4;
			SOFF_T(pdata,0,pos); /* current offset */
			pdata += 8;
			SIVAL(pdata,0,mode); /* is this the right sort of mode info? */
			pdata += 4;
			pdata += 4; /* alignment */
			len = srvstr_push(outbuf, pdata+4, fname, -1, STR_TERMINATE);
			SIVAL(pdata,0,len);
			pdata += 4 + len;
			data_size = PTR_DIFF(pdata,(*ppdata));
			break;

		case SMB_FILE_INTERNAL_INFORMATION:
			/* This should be an index number - looks like dev/ino to me :-) */
			SIVAL(pdata,0,sbuf.st_dev);
			SIVAL(pdata,4,sbuf.st_ino);
			data_size = 8;
			break;

		case SMB_FILE_ACCESS_INFORMATION:
			SIVAL(pdata,0,0x12019F); /* ??? */
			data_size = 4;
			break;

		case SMB_FILE_NAME_INFORMATION:
			/* Pathname with leading '\'. */
			{
				pstring new_fname;
				size_t byte_len;

				pstrcpy(new_fname, "\\");
				pstrcat(new_fname, fname);
				byte_len = dos_PutUniCode(pdata+4,new_fname,max_data_bytes,False);
				SIVAL(pdata,0,byte_len);
				data_size = 4 + byte_len;
				break;
			}

		case SMB_FILE_DISPOSITION_INFORMATION:
			data_size = 1;
			CVAL(pdata,0) = delete_pending;
			break;

		case SMB_FILE_POSITION_INFORMATION:
			data_size = 8;
			SOFF_T(pdata,0,pos);
			break;

		case SMB_FILE_MODE_INFORMATION:
			SIVAL(pdata,0,mode);
			data_size = 4;
			break;

		case SMB_FILE_ALIGNMENT_INFORMATION:
			SIVAL(pdata,0,0); /* No alignment needed. */
			data_size = 4;
			break;

#if 0
	/* Not yet finished... JRA */
	case 1018:
		{
			pstring new_fname;
			size_t byte_len;

			put_long_date(pdata,c_time);
			put_long_date(pdata+8,sbuf.st_atime);
			put_long_date(pdata+16,sbuf.st_mtime); /* write time */
			put_long_date(pdata+24,sbuf.st_mtime); /* change time */
			SIVAL(pdata,32,mode);
			SIVAL(pdata,36,0); /* ??? */
			SIVAL(pdata,40,0x20); /* ??? */
			SIVAL(pdata,44,0); /* ??? */
			SOFF_T(pdata,48,size);
			SIVAL(pdata,56,0x1); /* ??? */
			SIVAL(pdata,60,0); /* ??? */
			SIVAL(pdata,64,0); /* ??? */
			SIVAL(pdata,68,length); /* Following string length in bytes. */
			dos_PutUniCode(pdata+72,,False);
			break;
		}
#endif

		case SMB_FILE_ALTERNATE_NAME_INFORMATION:
			/* Last component of pathname. */
			{
				size_t byte_len = dos_PutUniCode(pdata+4,fname,max_data_bytes,False);
				SIVAL(pdata,0,byte_len);
				data_size = 4 + byte_len;
				break;
			}
		
		case SMB_FILE_STREAM_INFORMATION:
			if (mode & aDIR) {
				data_size = 0;
			} else {
				size_t byte_len = dos_PutUniCode(pdata+24,"::$DATA", 0xE, False);
				SIVAL(pdata,0,0); /* ??? */
				SIVAL(pdata,4,byte_len); /* Byte length of unicode string ::$DATA */
				SOFF_T(pdata,8,size);
				SIVAL(pdata,16,allocation_size);
				SIVAL(pdata,20,0); /* ??? */
				data_size = 24 + byte_len;
			}
			break;

		case SMB_FILE_COMPRESSION_INFORMATION:
			SOFF_T(pdata,0,size);
			SIVAL(pdata,8,0); /* ??? */
			SIVAL(pdata,12,0); /* ??? */
			data_size = 16;
			break;

		case SMB_FILE_NETWORK_OPEN_INFORMATION:
			put_long_date(pdata,c_time);
			put_long_date(pdata+8,sbuf.st_atime);
			put_long_date(pdata+16,sbuf.st_mtime); /* write time */
			put_long_date(pdata+24,sbuf.st_mtime); /* change time */
			SIVAL(pdata,32,allocation_size);
			SOFF_T(pdata,40,size);
			SIVAL(pdata,48,mode);
			SIVAL(pdata,52,0); /* ??? */
			data_size = 56;
			break;

		case SMB_FILE_ATTRIBUTE_TAG_INFORMATION:
			SIVAL(pdata,0,mode);
			SIVAL(pdata,4,0);
			data_size = 8;
			break;

#if 0
		/* NT4 server just returns "invalid query" to this - if we try to answer 
				it then NTws gets a BSOD! (tridge) */
		case SMB_QUERY_FILE_STREAM_INFO:
			SIVAL(pdata,0,pos);
			SIVAL(pdata,4,(uint32)size);
			SIVAL(pdata,12,(uint32)allocation_size);
			len = srvstr_push(outbuf, pdata+24, fname, -1, STR_TERMINATE);
			SIVAL(pdata,20,len);
			data_size = 24 + len;
			break;
#endif

		default:
			return ERROR_DOS(ERRDOS,ERRunknownlevel);
	}

	send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, data_size);

	return(-1);
}

/****************************************************************************
 Deal with the internal needs of setting the delete on close flag. Note that
 as the tdb locking is recursive, it is safe to call this from within 
 open_file_shared. JRA.
****************************************************************************/

NTSTATUS set_delete_on_close_internal(files_struct *fsp, BOOL delete_on_close)
{
	/*
	 * Only allow delete on close for writable shares.
	 */

	if (delete_on_close && !CAN_WRITE(fsp->conn)) {
		DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but write access denied on share.\n",
				fsp->fsp_name ));
				return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * Only allow delete on close for files/directories opened with delete intent.
	 */

	if (delete_on_close && !GET_DELETE_ACCESS_REQUESTED(fsp->share_mode)) {
		DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but delete access denied.\n",
				fsp->fsp_name ));
				return NT_STATUS_ACCESS_DENIED;
	}

	if(fsp->is_directory) {
		fsp->directory_delete_on_close = delete_on_close;
		DEBUG(10, ("set_delete_on_close_internal: %s delete on close flag for fnum = %d, directory %s\n",
			delete_on_close ? "Added" : "Removed", fsp->fnum, fsp->fsp_name ));
	} else if(fsp->stat_open) {

		DEBUG(10, ("set_delete_on_close_internal: %s delete on close flag for fnum = %d, stat open %s\n",
			delete_on_close ? "Added" : "Removed", fsp->fnum, fsp->fsp_name ));

	} else {

		files_struct *iterate_fsp;

		/*
		 * Modify the share mode entry for all files open
		 * on this device and inode to tell other smbds we have 
		 * changed the delete on close flag. This will be noticed
		 * in the close code, the last closer will delete the file
		 * if flag is set.
		 */

		DEBUG(10,("set_delete_on_close_internal: %s delete on close flag for fnum = %d, file %s\n",
					delete_on_close ? "Adding" : "Removing", fsp->fnum, fsp->fsp_name ));

		if (lock_share_entry_fsp(fsp) == False)
				return NT_STATUS_ACCESS_DENIED;

		if (!modify_delete_flag(fsp->dev, fsp->inode, delete_on_close)) {
			DEBUG(0,("set_delete_on_close_internal: failed to change delete on close flag for file %s\n",
					fsp->fsp_name ));
			unlock_share_entry_fsp(fsp);
			return NT_STATUS_ACCESS_DENIED;
		}

		/*
		 * Release the lock.
		 */

		unlock_share_entry_fsp(fsp);

		/*
		 * Go through all files we have open on the same device and
		 * inode (hanging off the same hash bucket) and set the DELETE_ON_CLOSE_FLAG.
		 * Other smbd's that have this file open will look in the share_mode on close.
		 * take care of this (rare) case in close_file(). See the comment there.
		 * NB. JRA. We don't really need to do this anymore - all should be taken
		 * care of in the share_mode changes in the tdb.
		 */

		for(iterate_fsp = file_find_di_first(fsp->dev, fsp->inode);
				iterate_fsp; iterate_fsp = file_find_di_next(iterate_fsp))
						fsp->delete_on_close = delete_on_close;

		/*
		 * Set the delete on close flag in the fsp.
		 */
		fsp->delete_on_close = delete_on_close;

		DEBUG(10, ("set_delete_on_close_internal: %s delete on close flag for fnum = %d, file %s\n",
			delete_on_close ? "Added" : "Removed", fsp->fnum, fsp->fsp_name ));

	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a TRANS2_SETFILEINFO (set file info by fileid).
****************************************************************************/

static int call_trans2setfilepathinfo(connection_struct *conn,
				      char *inbuf, char *outbuf, int length, 
				      int bufsize, char **pparams, 
				      char **ppdata, int total_data)
{
	char *params = *pparams;
	char *pdata = *ppdata;
	uint16 tran_call = SVAL(inbuf, smb_setup0);
	uint16 info_level;
	int mode=0;
	SMB_OFF_T size=0;
	struct utimbuf tvs;
	SMB_STRUCT_STAT sbuf;
	pstring fname;
	int fd = -1;
	BOOL bad_path = False;
	files_struct *fsp = NULL;

	if (tran_call == TRANSACT2_SETFILEINFO) {
		fsp = file_fsp(params,0);
		info_level = SVAL(params,2);    

		if(fsp && (fsp->is_directory || fsp->stat_open)) {
			/*
			 * This is actually a SETFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			pstrcpy(fname, fsp->fsp_name);
			unix_convert(fname,conn,0,&bad_path,&sbuf);
			if (!check_name(fname,conn) || (!VALID_STAT(sbuf))) {
				DEBUG(3,("fileinfo of %s failed (%s)\n",fname,strerror(errno)));
				if((errno == ENOENT) && bad_path) {
					unix_ERR_class = ERRDOS;
					unix_ERR_code = ERRbadpath;
				}
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}
		} else if (fsp && fsp->print_file) {
			/*
			 * Doing a DELETE_ON_CLOSE should cancel a print job.
			 */
			if ((info_level == SMB_SET_FILE_DISPOSITION_INFO) && CVAL(pdata,0)) {
				fsp->share_mode = FILE_DELETE_ON_CLOSE;

				DEBUG(3,("call_trans2setfilepathinfo: Cancelling print job (%s)\n", fsp->fsp_name ));
	
				SSVAL(params,0,0);
				send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
				return(-1);
			}
	    } else {
			/*
			 * Original code - this is an open file.
			 */
			CHECK_FSP(fsp,conn);

			pstrcpy(fname, fsp->fsp_name);
			fd = fsp->fd;

			if (vfs_fstat(fsp,fd,&sbuf) != 0) {
				DEBUG(3,("fstat of fnum %d failed (%s)\n",fsp->fnum, strerror(errno)));
				return(UNIXERROR(ERRDOS,ERRbadfid));
			}
		}
	} else {
		/* set path info */
		info_level = SVAL(params,0);    
		srvstr_pull(inbuf, fname, &params[6], sizeof(fname), -1, STR_TERMINATE);
		unix_convert(fname,conn,0,&bad_path,&sbuf);
		if(!check_name(fname, conn)) {
			if((errno == ENOENT) && bad_path) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}
 
		if(!VALID_STAT(sbuf)) {
			DEBUG(3,("stat of %s failed (%s)\n", fname, strerror(errno)));
			if((errno == ENOENT) && bad_path) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}    
	}

	if (!CAN_WRITE(conn))
		return ERROR_DOS(ERRSRV,ERRaccess);

	DEBUG(3,("call_trans2setfilepathinfo(%d) %s info_level=%d totdata=%d\n",
		tran_call,fname,info_level,total_data));

	/* Realloc the parameter and data sizes */
	params = Realloc(*pparams,2);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

	SSVAL(params,0,0);

	size = sbuf.st_size;
	tvs.modtime = sbuf.st_mtime;
	tvs.actime = sbuf.st_atime;
	mode = dos_mode(conn,fname,&sbuf);

	if (total_data > 4 && IVAL(pdata,0) == total_data) {
		/* uggh, EAs for OS2 */
		DEBUG(4,("Rejecting EA request with total_data=%d\n",total_data));
		return ERROR_DOS(ERRDOS,ERReasnotsupported);
	}

	switch (info_level) {
		case SMB_INFO_STANDARD:
		case SMB_INFO_QUERY_EA_SIZE:
		{
			/* access time */
			tvs.actime = make_unix_date2(pdata+l1_fdateLastAccess);

			/* write time */
			tvs.modtime = make_unix_date2(pdata+l1_fdateLastWrite);

			mode = SVAL(pdata,l1_attrFile);
			size = IVAL(pdata,l1_cbFile);
			break;
		}

		/* XXXX um, i don't think this is right.
			it's also not in the cifs6.txt spec.
		*/
		case SMB_INFO_QUERY_EAS_FROM_LIST:
			tvs.actime = make_unix_date2(pdata+8);
			tvs.modtime = make_unix_date2(pdata+12);
			size = IVAL(pdata,16);
			mode = IVAL(pdata,24);
			break;

		/* XXXX nor this.  not in cifs6.txt, either. */
		case SMB_INFO_QUERY_ALL_EAS:
			tvs.actime = make_unix_date2(pdata+8);
			tvs.modtime = make_unix_date2(pdata+12);
			size = IVAL(pdata,16);
			mode = IVAL(pdata,24);
			break;

		case SMB_SET_FILE_BASIC_INFO:
		case SMB_FILE_BASIC_INFORMATION:
		{
			/* Patch to do this correctly from Paul Eggert <eggert@twinsun.com>. */
			time_t write_time;
			time_t changed_time;

			/* Ignore create time at offset pdata. */

			/* access time */
			tvs.actime = interpret_long_date(pdata+8);

			write_time = interpret_long_date(pdata+16);
			changed_time = interpret_long_date(pdata+24);

			tvs.modtime = MIN(write_time, changed_time);

			/* Prefer a defined time to an undefined one. */
			if (tvs.modtime == (time_t)0 || tvs.modtime == (time_t)-1)
				tvs.modtime = (write_time == (time_t)0 || write_time == (time_t)-1
					? changed_time : write_time);

			/* attributes */
			mode = IVAL(pdata,32);
			break;
		}

		case  SMB_FILE_ALLOCATION_INFORMATION:
		case SMB_SET_FILE_ALLOCATION_INFO:
		{
			int ret = -1;
			SMB_OFF_T allocation_size = IVAL(pdata,0);
#ifdef LARGE_SMB_OFF_T
			allocation_size |= (((SMB_OFF_T)IVAL(pdata,4)) << 32);
#else /* LARGE_SMB_OFF_T */
			if (IVAL(pdata,4) != 0) /* more than 32 bits? */
				return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif /* LARGE_SMB_OFF_T */
			DEBUG(10,("call_trans2setfilepathinfo: Set file allocation info for file %s to %.0f\n",
					fname, (double)allocation_size ));

			if(allocation_size != sbuf.st_size) {
				SMB_STRUCT_STAT new_sbuf;
 
				DEBUG(10,("call_trans2setfilepathinfo: file %s : setting new allocation size to %.0f\n",
					fname, (double)allocation_size ));
 
				if (fd == -1) {
					files_struct *new_fsp = NULL;
					int access_mode = 0;
					int action = 0;
 
					if(global_oplock_break) {
						/* Queue this file modify as we are the process of an oplock break.  */
 
						DEBUG(2,("call_trans2setfilepathinfo: queueing message due to being "));
						DEBUGADD(2,( "in oplock break state.\n"));
 
						push_oplock_pending_smb_message(inbuf, length);
						return -1;
					}
 
					new_fsp = open_file_shared(conn, fname, &sbuf,
									SET_OPEN_MODE(DOS_OPEN_RDWR),
									(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
									0, 0, &access_mode, &action);
 
					if (new_fsp == NULL)
						return(UNIXERROR(ERRDOS,ERRbadpath));
					ret = vfs_allocate_file_space(new_fsp, allocation_size);
					if (vfs_fstat(new_fsp,new_fsp->fd,&new_sbuf) != 0) {
						DEBUG(3,("fstat of fnum %d failed (%s)\n",new_fsp->fnum, strerror(errno)));
						ret = -1;
					}
					close_file(new_fsp,True);
				} else {
					ret = vfs_allocate_file_space(fsp, size);
					if (vfs_fstat(fsp,fd,&new_sbuf) != 0) {
						DEBUG(3,("fstat of fnum %d failed (%s)\n",fsp->fnum, strerror(errno)));
						ret = -1;
					}
				}
				if (ret == -1)
					return ERROR_NT(NT_STATUS_DISK_FULL);

				/* Allocate can trucate size... */
				size = new_sbuf.st_size;
			}

			break;
		}

	case SMB_FILE_END_OF_FILE_INFORMATION:
		case SMB_SET_FILE_END_OF_FILE_INFO:
		{
			size = IVAL(pdata,0);
#ifdef LARGE_SMB_OFF_T
			size |= (((SMB_OFF_T)IVAL(pdata,4)) << 32);
#else /* LARGE_SMB_OFF_T */
			if (IVAL(pdata,4) != 0)	/* more than 32 bits? */
				return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif /* LARGE_SMB_OFF_T */
			DEBUG(10,("call_trans2setfilepathinfo: Set end of file info for file %s to %.0f\n", fname, (double)size ));
			break;
		}

		case SMB_FILE_DISPOSITION_INFORMATION:
		case SMB_SET_FILE_DISPOSITION_INFO: /* Set delete on close for open file. */
		{
			BOOL delete_on_close = (CVAL(pdata,0) ? True : False);
			NTSTATUS status;

			if (tran_call != TRANSACT2_SETFILEINFO)
				return ERROR_DOS(ERRDOS,ERRunknownlevel);

			if (fsp == NULL)
				return(UNIXERROR(ERRDOS,ERRbadfid));

			status = set_delete_on_close_internal(fsp, delete_on_close);
 
			if (NT_STATUS_V(status) !=  NT_STATUS_V(NT_STATUS_OK))
				return ERROR_NT(status);

			break;
		}

		default:
			return ERROR_DOS(ERRDOS,ERRunknownlevel);
	}

	/* get some defaults (no modifications) if any info is zero or -1. */
	if (tvs.actime == (time_t)0 || tvs.actime == (time_t)-1)
		tvs.actime = sbuf.st_atime;

	if (tvs.modtime == (time_t)0 || tvs.modtime == (time_t)-1)
		tvs.modtime = sbuf.st_mtime;

	DEBUG(6,("actime: %s " , ctime(&tvs.actime)));
	DEBUG(6,("modtime: %s ", ctime(&tvs.modtime)));
	DEBUG(6,("size: %.0f ", (double)size));
	DEBUG(6,("mode: %x\n"  , mode));

	if(!((info_level == SMB_SET_FILE_END_OF_FILE_INFO) ||
		(info_level == SMB_SET_FILE_ALLOCATION_INFO) ||
		(info_level == SMB_FILE_ALLOCATION_INFORMATION) ||
			(info_level == SMB_FILE_END_OF_FILE_INFORMATION))) {

		/*
		 * Only do this test if we are not explicitly
		 * changing the size of a file.
		 */
		if (!size)
			size = sbuf.st_size;
	}

	/*
	 * Try and set the times, size and mode of this file -
	 * if they are different from the current values
	 */
	if (sbuf.st_mtime != tvs.modtime || sbuf.st_atime != tvs.actime) {
		if(fsp != NULL) {
			/*
			 * This was a setfileinfo on an open file.
			 * NT does this a lot. It's actually pointless
			 * setting the time here, as it will be overwritten
			 * on the next write, so we save the request
			 * away and will set it on file code. JRA.
			 */

			if (tvs.modtime != (time_t)0 && tvs.modtime != (time_t)-1) {
				DEBUG(10,("call_trans2setfilepathinfo: setting pending modtime to %s\n", ctime(&tvs.modtime) ));
				fsp->pending_modtime = tvs.modtime;
			}

		} else {

			DEBUG(10,("call_trans2setfilepathinfo: setting utimes to modified values.\n"));

			if(file_utime(conn, fname, &tvs)!=0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	}

	/* check the mode isn't different, before changing it */
	if ((mode != 0) && (mode != dos_mode(conn, fname, &sbuf))) {

		DEBUG(10,("call_trans2setfilepathinfo: file %s : setting dos mode %x\n", fname, mode ));

		if(file_chmod(conn, fname, mode, NULL)) {
			DEBUG(2,("chmod of %s failed (%s)\n", fname, strerror(errno)));
			return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	}

	if(size != sbuf.st_size) {

		DEBUG(10,("call_trans2setfilepathinfo: file %s : setting new size to %.0f\n",
			fname, (double)size ));

		if (fd == -1) {
			files_struct *new_fsp = NULL;
			int access_mode = 0;
			int action = 0;

			if(global_oplock_break) {
				/* Queue this file modify as we are the process of an oplock break.  */

				DEBUG(2,("call_trans2setfilepathinfo: queueing message due to being "));
				DEBUGADD(2,( "in oplock break state.\n"));

				push_oplock_pending_smb_message(inbuf, length);
				return -1;
			}

			new_fsp = open_file_shared(conn, fname, &sbuf,
						SET_OPEN_MODE(DOS_OPEN_RDWR),
						(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
						0, 0, &access_mode, &action);
	
			if (new_fsp == NULL)
				return(UNIXERROR(ERRDOS,ERRbadpath));
			vfs_set_filelen(new_fsp, size);
			close_file(new_fsp,True);
		} else {
			vfs_set_filelen(fsp, size);
		}
	}

	SSVAL(params,0,0);

	send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
  
	return(-1);
}

/****************************************************************************
 Reply to a TRANS2_MKDIR (make directory with extended attributes).
****************************************************************************/

static int call_trans2mkdir(connection_struct *conn,
			    char *inbuf, char *outbuf, int length, int bufsize,
			    char **pparams, char **ppdata)
{
  char *params = *pparams;
  pstring directory;
  int ret = -1;
  SMB_STRUCT_STAT sbuf;
  BOOL bad_path = False;

  if (!CAN_WRITE(conn))
    return ERROR_DOS(ERRSRV,ERRaccess);

  srvstr_pull(inbuf, directory, &params[4], sizeof(directory), -1, STR_TERMINATE);

  DEBUG(3,("call_trans2mkdir : name = %s\n", directory));

  unix_convert(directory,conn,0,&bad_path,&sbuf);
  if (check_name(directory,conn))
    ret = vfs_mkdir(conn,directory,unix_mode(conn,aDIR,directory));
  
  if(ret < 0)
    {
      DEBUG(5,("call_trans2mkdir error (%s)\n", strerror(errno)));
      if((errno == ENOENT) && bad_path)
      {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      return(UNIXERROR(ERRDOS,ERRnoaccess));
    }

  /* Realloc the parameter and data sizes */
  params = Realloc(*pparams,2);
  if(params == NULL) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *pparams	= params;

  SSVAL(params,0,0);

  send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
 Reply to a TRANS2_FINDNOTIFYFIRST (start monitoring a directory for changes).
 We don't actually do this - we just send a null response.
****************************************************************************/

static int call_trans2findnotifyfirst(connection_struct *conn,
				      char *inbuf, char *outbuf, 
				      int length, int bufsize,
				      char **pparams, char **ppdata)
{
  static uint16 fnf_handle = 257;
  char *params = *pparams;
  uint16 info_level = SVAL(params,4);

  DEBUG(3,("call_trans2findnotifyfirst - info_level %d\n", info_level));

  switch (info_level) 
    {
    case 1:
    case 2:
      break;
    default:
      return ERROR_DOS(ERRDOS,ERRunknownlevel);
    }

  /* Realloc the parameter and data sizes */
  params = Realloc(*pparams,6);
  if(params == NULL) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *pparams	= params;

  SSVAL(params,0,fnf_handle);
  SSVAL(params,2,0); /* No changes */
  SSVAL(params,4,0); /* No EA errors */

  fnf_handle++;

  if(fnf_handle == 0)
    fnf_handle = 257;

  send_trans2_replies(outbuf, bufsize, params, 6, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
 Reply to a TRANS2_FINDNOTIFYNEXT (continue monitoring a directory for 
 changes). Currently this does nothing.
****************************************************************************/

static int call_trans2findnotifynext(connection_struct *conn,
				     char *inbuf, char *outbuf, 
				     int length, int bufsize,
				     char **pparams, char **ppdata)
{
  char *params = *pparams;

  DEBUG(3,("call_trans2findnotifynext\n"));

  /* Realloc the parameter and data sizes */
  params = Realloc(*pparams,4);
  if(params == NULL) {
    return ERROR_DOS(ERRDOS,ERRnomem);
  }
  *pparams	= params;

  SSVAL(params,0,0); /* No changes */
  SSVAL(params,2,0); /* No EA errors */

  send_trans2_replies(outbuf, bufsize, params, 4, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
 Reply to a TRANS2_GET_DFS_REFERRAL - Shirish Kalele <kalele@veritas.com>.
****************************************************************************/

static int call_trans2getdfsreferral(connection_struct *conn, char* inbuf,
				     char* outbuf, int length, int bufsize,
				     char** pparams, char** ppdata)
{
  char *params = *pparams;
  pstring pathname;
  int reply_size = 0;
  int max_referral_level = SVAL(params,0);


  DEBUG(10,("call_trans2getdfsreferral\n"));

  if(!lp_host_msdfs())
    return ERROR_DOS(ERRDOS,ERRbadfunc);

  srvstr_pull(inbuf, pathname, &params[2], sizeof(pathname), -1, STR_TERMINATE);

  if((reply_size = setup_dfs_referral(pathname,max_referral_level,ppdata)) < 0)
    return ERROR_DOS(ERRDOS,ERRbadfile);
    
  SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | FLAGS2_DFS_PATHNAMES);
  send_trans2_replies(outbuf,bufsize,0,0,*ppdata,reply_size);

  return(-1);
}

#define LMCAT_SPL       0x53
#define LMFUNC_GETJOBID 0x60

/****************************************************************************
 Reply to a TRANS2_IOCTL - used for OS/2 printing.
****************************************************************************/

static int call_trans2ioctl(connection_struct *conn, char* inbuf,
                            char* outbuf, int length, int bufsize,
                            char** pparams, char** ppdata)
{
  char *pdata = *ppdata;
  files_struct *fsp = file_fsp(inbuf,smb_vwv15);

  if ((SVAL(inbuf,(smb_setup+4)) == LMCAT_SPL) &&
      (SVAL(inbuf,(smb_setup+6)) == LMFUNC_GETJOBID)) {
    pdata = Realloc(*ppdata, 32);
    if(pdata == NULL) {
      return ERROR_DOS(ERRDOS,ERRnomem);
    }
    *ppdata = pdata;

	/* NOTE - THIS IS ASCII ONLY AT THE MOMENT - NOT SURE IF OS/2
	   CAN ACCEPT THIS IN UNICODE. JRA. */

    SSVAL(pdata,0,fsp->print_jobid);                     /* Job number */
	srvstr_push( outbuf, pdata + 2, global_myname, 15, STR_ASCII|STR_TERMINATE); /* Our NetBIOS name */
    srvstr_push( outbuf, pdata+18, lp_servicename(SNUM(conn)), 13, STR_ASCII|STR_TERMINATE); /* Service name */
    send_trans2_replies(outbuf,bufsize,*pparams,0,*ppdata,32);
    return(-1);
  } else {
    DEBUG(2,("Unknown TRANS2_IOCTL\n"));
    return ERROR_DOS(ERRSRV,ERRerror);
  }
}

/****************************************************************************
 Reply to a SMBfindclose (stop trans2 directory search).
****************************************************************************/

int reply_findclose(connection_struct *conn,
		    char *inbuf,char *outbuf,int length,int bufsize)
{
	int outsize = 0;
	int dptr_num=SVALS(inbuf,smb_vwv0);
	START_PROFILE(SMBfindclose);

	DEBUG(3,("reply_findclose, dptr_num = %d\n", dptr_num));

	dptr_close(&dptr_num);

	outsize = set_message(outbuf,0,0,True);

	DEBUG(3,("SMBfindclose dptr_num = %d\n", dptr_num));

	END_PROFILE(SMBfindclose);
	return(outsize);
}

/****************************************************************************
 Reply to a SMBfindnclose (stop FINDNOTIFYFIRST directory search).
****************************************************************************/

int reply_findnclose(connection_struct *conn, 
		     char *inbuf,char *outbuf,int length,int bufsize)
{
	int outsize = 0;
	int dptr_num= -1;
	START_PROFILE(SMBfindnclose);
	
	dptr_num = SVAL(inbuf,smb_vwv0);

	DEBUG(3,("reply_findnclose, dptr_num = %d\n", dptr_num));

	/* We never give out valid handles for a 
	   findnotifyfirst - so any dptr_num is ok here. 
	   Just ignore it. */

	outsize = set_message(outbuf,0,0,True);

	DEBUG(3,("SMB_findnclose dptr_num = %d\n", dptr_num));

	END_PROFILE(SMBfindnclose);
	return(outsize);
}

/****************************************************************************
 Reply to a SMBtranss2 - just ignore it!
****************************************************************************/

int reply_transs2(connection_struct *conn,
		  char *inbuf,char *outbuf,int length,int bufsize)
{
	START_PROFILE(SMBtranss2);
	DEBUG(4,("Ignoring transs2 of length %d\n",length));
	END_PROFILE(SMBtranss2);
	return(-1);
}

/****************************************************************************
 Reply to a SMBtrans2.
****************************************************************************/

int reply_trans2(connection_struct *conn,
		 char *inbuf,char *outbuf,int length,int bufsize)
{
	int outsize = 0;
	unsigned int total_params = SVAL(inbuf, smb_tpscnt);
	unsigned int total_data =SVAL(inbuf, smb_tdscnt);
#if 0
	unsigned int max_param_reply = SVAL(inbuf, smb_mprcnt);
	unsigned int max_data_reply = SVAL(inbuf, smb_mdrcnt);
	unsigned int max_setup_fields = SVAL(inbuf, smb_msrcnt);
	BOOL close_tid = BITSETW(inbuf+smb_flags,0);
	BOOL no_final_response = BITSETW(inbuf+smb_flags,1);
	int32 timeout = IVALS(inbuf,smb_timeout);
#endif
	unsigned int suwcnt = SVAL(inbuf, smb_suwcnt);
	unsigned int tran_call = SVAL(inbuf, smb_setup0);
	char *params = NULL, *data = NULL;
	int num_params, num_params_sofar, num_data, num_data_sofar;
	START_PROFILE(SMBtrans2);

	if(global_oplock_break && (tran_call == TRANSACT2_OPEN)) {
		/* Queue this open message as we are the process of an
		 * oplock break.  */

		DEBUG(2,("reply_trans2: queueing message trans2open due to being "));
		DEBUGADD(2,( "in oplock break state.\n"));

		push_oplock_pending_smb_message(inbuf, length);
		END_PROFILE(SMBtrans2);
		return -1;
	}
	
	if (IS_IPC(conn) && (tran_call != TRANSACT2_OPEN)
            && (tran_call != TRANSACT2_GET_DFS_REFERRAL)) {
		END_PROFILE(SMBtrans2);
		return ERROR_DOS(ERRSRV,ERRaccess);
	}

	outsize = set_message(outbuf,0,0,True);

	/* All trans2 messages we handle have smb_sucnt == 1 - ensure this
	   is so as a sanity check */
	if (suwcnt != 1) {
		/*
		 * Need to have rc=0 for ioctl to get job id for OS/2.
		 *  Network printing will fail if function is not successful.
		 *  Similar function in reply.c will be used if protocol
		 *  is LANMAN1.0 instead of LM1.2X002.
		 *  Until DosPrintSetJobInfo with PRJINFO3 is supported,
		 *  outbuf doesn't have to be set(only job id is used).
		 */
		if ( (suwcnt == 4) && (tran_call == TRANSACT2_IOCTL) &&
				(SVAL(inbuf,(smb_setup+4)) == LMCAT_SPL) &&
				(SVAL(inbuf,(smb_setup+6)) == LMFUNC_GETJOBID)) {
			DEBUG(2,("Got Trans2 DevIOctl jobid\n"));
		} else {
			DEBUG(2,("Invalid smb_sucnt in trans2 call(%d)\n",suwcnt));
			DEBUG(2,("Transaction is %d\n",tran_call));
			END_PROFILE(SMBtrans2);
			return ERROR_DOS(ERRSRV,ERRerror);
		}
	}
    
	/* Allocate the space for the maximum needed parameters and data */
	if (total_params > 0)
		params = (char *)malloc(total_params);
	if (total_data > 0)
		data = (char *)malloc(total_data);
  
	if ((total_params && !params)  || (total_data && !data)) {
		DEBUG(2,("Out of memory in reply_trans2\n"));
		SAFE_FREE(params);
		SAFE_FREE(data); 
		END_PROFILE(SMBtrans2);
		return ERROR_DOS(ERRDOS,ERRnomem);
	}

	/* Copy the param and data bytes sent with this request into
	   the params buffer */
	num_params = num_params_sofar = SVAL(inbuf,smb_pscnt);
	num_data = num_data_sofar = SVAL(inbuf, smb_dscnt);

	if (num_params > total_params || num_data > total_data)
		exit_server("invalid params in reply_trans2");

	if(params)
		memcpy( params, smb_base(inbuf) + SVAL(inbuf, smb_psoff), num_params);
	if(data)
		memcpy( data, smb_base(inbuf) + SVAL(inbuf, smb_dsoff), num_data);

	if(num_data_sofar < total_data || num_params_sofar < total_params)  {
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf,0,0,True);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_trans2: send_smb failed.");

		while (num_data_sofar < total_data || 
		       num_params_sofar < total_params) {
			BOOL ret;

			ret = receive_next_smb(inbuf,bufsize,SMB_SECONDARY_WAIT);
			
			if ((ret && 
			     (CVAL(inbuf, smb_com) != SMBtranss2)) || !ret) {
				outsize = set_message(outbuf,0,0,True);
				if(ret)
					DEBUG(0,("reply_trans2: Invalid secondary trans2 packet\n"));
				else
					DEBUG(0,("reply_trans2: %s in getting secondary trans2 response.\n",
						 (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
				SAFE_FREE(params);
				SAFE_FREE(data);
				END_PROFILE(SMBtrans2);
				return ERROR_DOS(ERRSRV,ERRerror);
			}
      
			/* Revise total_params and total_data in case
                           they have changed downwards */
			total_params = SVAL(inbuf, smb_tpscnt);
			total_data = SVAL(inbuf, smb_tdscnt);
			num_params_sofar += (num_params = SVAL(inbuf,smb_spscnt));
			num_data_sofar += ( num_data = SVAL(inbuf, smb_sdscnt));
			if (num_params_sofar > total_params || num_data_sofar > total_data)
				exit_server("data overflow in trans2");
			
			memcpy( &params[ SVAL(inbuf, smb_spsdisp)], 
				smb_base(inbuf) + SVAL(inbuf, smb_spsoff), num_params);
			memcpy( &data[SVAL(inbuf, smb_sdsdisp)],
				smb_base(inbuf)+ SVAL(inbuf, smb_sdsoff), num_data);
		}
	}
	
	if (Protocol >= PROTOCOL_NT1) {
		SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | 0x40); /* IS_LONG_NAME */
	}

	/* Now we must call the relevant TRANS2 function */
	switch(tran_call)  {
	case TRANSACT2_OPEN:
		START_PROFILE_NESTED(Trans2_open);
		outsize = call_trans2open(conn, 
					  inbuf, outbuf, bufsize, 
					  &params, &data);
		END_PROFILE_NESTED(Trans2_open);
		break;

	case TRANSACT2_FINDFIRST:
		START_PROFILE_NESTED(Trans2_findfirst);
		outsize = call_trans2findfirst(conn, inbuf, outbuf, 
					       bufsize, &params, &data);
		END_PROFILE_NESTED(Trans2_findfirst);
		break;

	case TRANSACT2_FINDNEXT:
		START_PROFILE_NESTED(Trans2_findnext);
		outsize = call_trans2findnext(conn, inbuf, outbuf, 
					      length, bufsize, 
					      &params, &data);
		END_PROFILE_NESTED(Trans2_findnext);
		break;

	case TRANSACT2_QFSINFO:
		START_PROFILE_NESTED(Trans2_qfsinfo);
	    outsize = call_trans2qfsinfo(conn, inbuf, outbuf, 
					 length, bufsize, &params, 
					 &data);
		END_PROFILE_NESTED(Trans2_qfsinfo);
	    break;

	case TRANSACT2_SETFSINFO:
		START_PROFILE_NESTED(Trans2_setfsinfo);
		outsize = call_trans2setfsinfo(conn, inbuf, outbuf, 
					       length, bufsize, 
					       &params, &data);
		END_PROFILE_NESTED(Trans2_setfsinfo);
		break;

	case TRANSACT2_QPATHINFO:
	case TRANSACT2_QFILEINFO:
		START_PROFILE_NESTED(Trans2_qpathinfo);
		outsize = call_trans2qfilepathinfo(conn, inbuf, outbuf, 
						   length, bufsize, 
						   &params, &data, total_data);
		END_PROFILE_NESTED(Trans2_qpathinfo);
		break;
	case TRANSACT2_SETPATHINFO:
	case TRANSACT2_SETFILEINFO:
		START_PROFILE_NESTED(Trans2_setpathinfo);
		outsize = call_trans2setfilepathinfo(conn, inbuf, outbuf, 
						     length, bufsize, 
						     &params, &data, 
						     total_data);
		END_PROFILE_NESTED(Trans2_setpathinfo);
		break;

	case TRANSACT2_FINDNOTIFYFIRST:
		START_PROFILE_NESTED(Trans2_findnotifyfirst);
		outsize = call_trans2findnotifyfirst(conn, inbuf, outbuf, 
						     length, bufsize, 
						     &params, &data);
		END_PROFILE_NESTED(Trans2_findnotifyfirst);
		break;

	case TRANSACT2_FINDNOTIFYNEXT:
		START_PROFILE_NESTED(Trans2_findnotifynext);
		outsize = call_trans2findnotifynext(conn, inbuf, outbuf, 
						    length, bufsize, 
						    &params, &data);
		END_PROFILE_NESTED(Trans2_findnotifynext);
		break;
	case TRANSACT2_MKDIR:
		START_PROFILE_NESTED(Trans2_mkdir);
		outsize = call_trans2mkdir(conn, inbuf, outbuf, length, 
					   bufsize, &params, &data);
		END_PROFILE_NESTED(Trans2_mkdir);
		break;

	case TRANSACT2_GET_DFS_REFERRAL:
		START_PROFILE_NESTED(Trans2_get_dfs_referral);
        outsize = call_trans2getdfsreferral(conn,inbuf,outbuf,length,
					    bufsize, &params, &data);
		END_PROFILE_NESTED(Trans2_get_dfs_referral);
		break;
	case TRANSACT2_IOCTL:
		START_PROFILE_NESTED(Trans2_ioctl);
		outsize = call_trans2ioctl(conn,inbuf,outbuf,length,
						bufsize,&params,&data);
		END_PROFILE_NESTED(Trans2_ioctl);
		break;
	default:
		/* Error in request */
		DEBUG(2,("Unknown request %d in trans2 call\n", tran_call));
		SAFE_FREE(params);
		SAFE_FREE(data);
		END_PROFILE(SMBtrans2);
		return ERROR_DOS(ERRSRV,ERRerror);
	}
	
	/* As we do not know how many data packets will need to be
	   returned here the various call_trans2xxxx calls
	   must send their own. Thus a call_trans2xxx routine only
	   returns a value other than -1 when it wants to send
	   an error packet. 
	*/
	
	SAFE_FREE(params);
	SAFE_FREE(data);
	END_PROFILE(SMBtrans2);
	return outsize; /* If a correct response was needed the
			   call_trans2xxx calls have already sent
			   it. If outsize != -1 then it is returning */
}
