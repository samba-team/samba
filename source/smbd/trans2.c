/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB transaction2 handling
   Extensively modified by Andrew Tridgell, 1995
   Copyright (C) Jeremy Allison 1994-2002

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

#define get_file_size(sbuf) ((sbuf).st_size)

/* given a stat buffer return the allocated size on disk, taking into
   account sparse files */

SMB_BIG_UINT get_allocation_size(files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	SMB_BIG_UINT ret;
#if defined(HAVE_STAT_ST_BLOCKS) && defined(STAT_ST_BLOCKSIZE)
	ret = (SMB_BIG_UINT)STAT_ST_BLOCKSIZE * (SMB_BIG_UINT)sbuf->st_blocks;
#else
	ret = (SMB_BIG_UINT)get_file_size(*sbuf);
#endif
	if (!ret && fsp && fsp->initial_allocation_size)
		ret = fsp->initial_allocation_size;
	ret = SMB_ROUNDUP(ret,SMB_ROUNDUP_ALLOCATION_SIZE);
	return ret;
}

/****************************************************************************
  Send the required number of replies back.
  We assume all fields other than the data fields are
  set correctly for the type of call.
  HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static int send_trans2_replies(char *outbuf, int bufsize, char *params, int paramsize, char *pdata, int datasize)
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

	if(params_to_send == 0 && data_to_send == 0) {
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

	useable_space = bufsize - ((smb_buf(outbuf)+ alignment_offset+data_alignment_offset) - outbuf);

	/* useable_space can never be more than max_send minus the alignment offset. */

	useable_space = MIN(useable_space, max_send - (alignment_offset+data_alignment_offset));


	while (params_to_send || data_to_send) {
		/* Calculate whether we will totally or partially fill this packet */

		total_sent_thistime = params_to_send + data_to_send + alignment_offset + data_alignment_offset;

		/* We can never send more than useable_space */
		/*
		 * Note that 'useable_space' does not include the alignment offsets,
		 * but we must include the alignment offsets in the calculation of
		 * the length of the data we send over the wire, as the alignment offsets
		 * are sent here. Fix from Marc_Jacobsen@hp.com.
		 */

		total_sent_thistime = MIN(total_sent_thistime, useable_space+ alignment_offset + data_alignment_offset);

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
		if(data_sent_thistime == 0) {
			SSVAL(outbuf,smb_droff,0);
			SSVAL(outbuf,smb_drdisp, 0);
		} else {
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

		if(params_to_send < 0 || data_to_send < 0) {
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

static int call_trans2open(connection_struct *conn, char *inbuf, char *outbuf, int bufsize,  
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *params = *pparams;
	int16 open_mode;
	int16 open_attr;
	BOOL oplock_request;
#if 0
	BOOL return_additional_info;
	int16 open_sattr;
	time_t open_time;
#endif
	int16 open_ofun;
	int32 open_size;
	char *pname;

	pstring fname;
	mode_t unixmode;
	SMB_OFF_T size=0;
	int fmode=0,mtime=0,rmode;
	SMB_INO_T inode = 0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	BOOL bad_path = False;
	files_struct *fsp;

	/*
	 * Ensure we have enough parameters to perform the operation.
	 */

	if (total_params < 29)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	open_mode = SVAL(params, 2);
	open_attr = SVAL(params,6);
	oplock_request = (((SVAL(params,0)|(1<<1))>>1) | ((SVAL(params,0)|(1<<2))>>1));
#if 0
	return_additional_info = BITSETW(params,0);
	open_sattr = SVAL(params, 4);
	open_time = make_unix_date3(params+8);
#endif
	open_ofun = SVAL(params,12);
	open_size = IVAL(params,14);
	pname = &params[28];

	pstrcpy(fname, pname);

	DEBUG(3,("trans2open %s mode=%d attr=%d ofun=%d size=%d\n",
		fname,open_mode, open_attr, open_ofun, open_size));

	if (IS_IPC(conn))
		return(ERROR_DOS(ERRSRV,ERRaccess));

	/* XXXX we need to handle passed times, sattr and flags */

	unix_convert(fname,conn,0,&bad_path,&sbuf);
    
	if (!check_name(fname,conn)) {
		set_bad_path_error(errno, bad_path);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	unixmode = unix_mode(conn,open_attr | aARCH, fname);
      
	fsp = open_file_shared(conn,fname,&sbuf,open_mode,open_ofun,unixmode,
			oplock_request, &rmode,&smb_action);
      
	if (!fsp) {
		set_bad_path_error(errno, bad_path);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	size = get_file_size(sbuf);
	fmode = dos_mode(conn,fname,&sbuf);
	mtime = sbuf.st_mtime;
	inode = sbuf.st_ino;
	if (fmode & aDIR) {
		close_file(fsp,False);
		return(ERROR_DOS(ERRDOS,ERRnoaccess));
	}

	/* Realloc the size of parameters and data we will return */
	params = Realloc(*pparams, 28);
	if( params == NULL )
		return(ERROR_DOS(ERRDOS,ERRnomem));
	*pparams = params;

	memset((char *)params,'\0',28);
	SSVAL(params,0,fsp->fnum);
	SSVAL(params,2,fmode);
	put_dos_date2(params,4, mtime);
	SIVAL(params,8, (uint32)size);
	SSVAL(params,12,rmode);

	if (oplock_request && lp_fake_oplocks(SNUM(conn)))
		smb_action |= EXTENDED_OPLOCK_GRANTED;

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
 Return the filetype for UNIX extensions.
****************************************************************************/

static uint32 unix_filetype(mode_t mode)
{
	if(S_ISREG(mode))
		return UNIX_TYPE_FILE;
	else if(S_ISDIR(mode))
		return UNIX_TYPE_DIR;
#ifdef S_ISLNK
	else if(S_ISLNK(mode))
		return UNIX_TYPE_SYMLINK;
#endif
#ifdef S_ISCHR
	else if(S_ISCHR(mode))
		return UNIX_TYPE_CHARDEV;
#endif
#ifdef S_ISBLK
	else if(S_ISBLK(mode))
		return UNIX_TYPE_BLKDEV;
#endif
#ifdef S_ISFIFO
	else if(S_ISFIFO(mode))
		return UNIX_TYPE_FIFO;
#endif
#ifdef S_ISSOCK
	else if(S_ISSOCK(mode))
		return UNIX_TYPE_SOCKET;
#endif

	DEBUG(0,("unix_filetype: unknown filetype %u", (unsigned)mode));
	return UNIX_TYPE_UNKNOWN;
}

/****************************************************************************
 Return the major devicenumber for UNIX extensions.
****************************************************************************/

static uint32 unix_dev_major(SMB_DEV_T dev)
{
#if defined(HAVE_DEVICE_MAJOR_FN)
	return (uint32)major(dev);
#else
	return (uint32)(dev >> 8);
#endif
}

/****************************************************************************
 Return the minor devicenumber for UNIX extensions.
****************************************************************************/

static uint32 unix_dev_minor(SMB_DEV_T dev)
{
#if defined(HAVE_DEVICE_MINOR_FN)
	return (uint32)minor(dev);
#else
	return (uint32)(dev & 0xff);
#endif
}

/****************************************************************************
 Map wire perms onto standard UNIX permissions. Obey share restrictions.
****************************************************************************/

static mode_t unix_perms_from_wire( connection_struct *conn, SMB_STRUCT_STAT *pst, uint32 perms)
{
	mode_t ret = 0;

	if (perms == SMB_MODE_NO_CHANGE)
		return pst->st_mode;

	ret |= ((perms & UNIX_X_OTH ) ? S_IXOTH : 0);
	ret |= ((perms & UNIX_W_OTH ) ? S_IWOTH : 0);
	ret |= ((perms & UNIX_R_OTH ) ? S_IROTH : 0);
	ret |= ((perms & UNIX_X_GRP ) ? S_IXGRP : 0);
	ret |= ((perms & UNIX_W_GRP ) ? S_IWGRP : 0);
	ret |= ((perms & UNIX_R_GRP ) ? S_IRGRP : 0);
	ret |= ((perms & UNIX_X_USR ) ? S_IXUSR : 0);
	ret |= ((perms & UNIX_W_USR ) ? S_IWUSR : 0);
	ret |= ((perms & UNIX_R_USR ) ? S_IRUSR : 0);
#ifdef S_ISVTX
	ret |= ((perms & UNIX_STICKY ) ? S_ISVTX : 0);
#endif
#ifdef S_ISGID
	ret |= ((perms & UNIX_SET_GID ) ? S_ISGID : 0);
#endif
#ifdef S_ISUID
	ret |= ((perms & UNIX_SET_UID ) ? S_ISUID : 0);
#endif

	if (VALID_STAT(*pst) && S_ISDIR(pst->st_mode)) {
		ret &= lp_dir_mask(SNUM(conn));
		/* Add in force bits */
		ret |= lp_force_dir_mode(SNUM(conn));
	} else {
		/* Apply mode mask */
		ret &= lp_create_mask(SNUM(conn));
		/* Add in force bits */
		ret |= lp_force_create_mode(SNUM(conn));
	}

	return ret;
}

/****************************************************************************
checks for SMB_TIME_NO_CHANGE and if not found
calls interpret_long_date
****************************************************************************/
time_t interpret_long_unix_date(char *p)
{
	DEBUG(1,("interpret_long_unix_date\n"));
	if(IVAL(p,0) == SMB_TIME_NO_CHANGE_LO &&
	   IVAL(p,4) == SMB_TIME_NO_CHANGE_HI) {
		return -1;
	} else {
		return interpret_long_date(p);
	}
}

/****************************************************************************
 Get a level dependent lanman2 dir entry.
****************************************************************************/

static BOOL get_lanman2_dir_entry(connection_struct *conn,
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
	char *p, *pdata = *ppdata;
	uint32 reskey=0;
	int prev_dirpos=0;
	int mode=0;
	SMB_OFF_T size = 0;
	SMB_BIG_UINT allocation_size = 0;
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

	p = strrchr(path_mask,'/');
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

		if(!got_match && !mangle_is_8_3(fname, False)) {

			/*
			 * It turns out that NT matches wildcards against
			 * both long *and* short names. This may explain some
			 * of the wildcard wierdness from old DOS clients
			 * that some people have been seeing.... JRA.
			 */

			pstring newname;
			pstrcpy( newname, fname);
			mangle_map( newname, True, False, SNUM(conn));
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

			if (INFO_LEVEL_IS_UNIX(info_level)) {
				if (vfs_lstat(conn,pathreal,&sbuf) != 0) {
					DEBUG(5,("get_lanman2_dir_entry:Couldn't lstat [%s] (%s)\n",
						pathreal,strerror(errno)));
					continue;
				}
			} else if (vfs_stat(conn,pathreal,&sbuf) != 0) {

				/* Needed to show the msdfs symlinks as 
				 * directories */

				if(lp_host_msdfs() && 
				   lp_msdfs_root(SNUM(conn)) &&
				   is_msdfs_link(conn, pathreal, NULL, NULL,
						 &sbuf)) {

					DEBUG(5,("get_lanman2_dir_entry: Masquerading msdfs link %s as a directory\n", pathreal));
					sbuf.st_mode = (sbuf.st_mode & 0xFFF) | S_IFDIR;

				} else {

					DEBUG(5,("get_lanman2_dir_entry:Couldn't stat [%s] (%s)\n",
						pathreal,strerror(errno)));
					continue;
				}
			}

			mode = dos_mode(conn,pathreal,&sbuf);

			if (!dir_check_ftype(conn,mode,&sbuf,dirtype)) {
				DEBUG(5,("[%s] attribs didn't match %x\n",fname,dirtype));
				continue;
			}

			size = get_file_size(sbuf);
			allocation_size = get_allocation_size(NULL,&sbuf);
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

	mangle_map(fname,False,True,SNUM(conn));

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
			SCVAL(p,l1_cchName,strlen(fname));
			pstrcpy(p + l1_achName, fname);
			nameptr = p + l1_achName;
			p += l1_achName + strlen(fname) + 1;
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
			SCVAL(p,l2_cchName,strlen(fname));
			pstrcpy(p + l2_achName, fname);
			nameptr = p + l2_achName;
			p += l2_achName + strlen(fname) + 1;
			break;

		case 3:
			SIVAL(p,0,reskey);
			put_dos_date2(p,4,cdate);
			put_dos_date2(p,8,adate);
			put_dos_date2(p,12,mdate);
			SIVAL(p,16,(uint32)size);
			SIVAL(p,20,(uint32)allocation_size);
			SSVAL(p,24,mode);
			SIVAL(p,26,4);
			SCVAL(p,30,strlen(fname));
			pstrcpy(p+31, fname);
			nameptr = p+31;
			p += 31 + strlen(fname) + 1;
			break;

		case 4:
			if(requires_resume_key) {
				SIVAL(p,0,reskey);
				p += 4;
			}
			SIVAL(p,0,33+strlen(fname)+1);
			put_dos_date2(p,4,cdate);
			put_dos_date2(p,8,adate);
			put_dos_date2(p,12,mdate);
			SIVAL(p,16,(uint32)size);
			SIVAL(p,20,(uint32)allocation_size);
			SSVAL(p,24,mode);
			SCVAL(p,32,strlen(fname));
			pstrcpy(p + 33, fname);
			nameptr = p+33;
			p += 33 + strlen(fname) + 1;
			break;

		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
			was_8_3 = mangle_is_8_3(fname, True);
			len = 94+strlen(fname);
			len = (len + 3) & ~3;
			SIVAL(p,0,len); p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size);
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			SIVAL(p,0,strlen(fname)); p += 4;
			SIVAL(p,0,0); p += 4;
			/* Clear the short name buffer. This is 
			 * IMPORTANT as not doing so will trigger
			 * a Win2k client bug. JRA.
			 */
			memset(p,'\0',26);
			if (!was_8_3) {
				fstring tmpname;
				fstrcpy(tmpname,fname);
				mangle_map(tmpname,True,True,SNUM(conn));
				strupper(tmpname);
				fstrcpy(p+2,tmpname);
				SSVAL(p, 0, strlen(tmpname));
			} else {
				SSVAL(p,0,0);
				*(p+2) = 0;
			}
			p += 2 + 24;
			/* nameptr = p;  */
			pstrcpy(p,fname); p += strlen(p);
			p = pdata + len;
			break;

		case SMB_FIND_FILE_DIRECTORY_INFO:
			len = 64+strlen(fname);
			len = (len + 3) & ~3;
			SIVAL(p,0,len); p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size);
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			SIVAL(p,0,strlen(fname)); p += 4;
			pstrcpy(p,fname);
			p = pdata + len;
			break;
      
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
			len = 68+strlen(fname);
			len = (len + 3) & ~3;
			SIVAL(p,0,len); p += 4;
			SIVAL(p,0,reskey); p += 4;
			put_long_date(p,cdate); p += 8;
			put_long_date(p,adate); p += 8;
			put_long_date(p,mdate); p += 8;
			put_long_date(p,mdate); p += 8;
			SOFF_T(p,0,size); 
			SOFF_T(p,8,allocation_size);
			p += 16;
			SIVAL(p,0,nt_extmode); p += 4;
			SIVAL(p,0,strlen(fname)); p += 4;
			SIVAL(p,0,0); p += 4;
			pstrcpy(p,fname);
			p = pdata + len;
			break;

		case SMB_FIND_FILE_NAMES_INFO:
			len = 12+strlen(fname);
			len = (len + 3) & ~3;
			SIVAL(p,0,len); p += 4;
			SIVAL(p,0,reskey); p += 4;
			SIVAL(p,0,strlen(fname)); p += 4;
			pstrcpy(p,fname);
			p = pdata + len;
			break;

		/* CIFS UNIX Extension. */

		case SMB_FIND_FILE_UNIX:
			len = 108+strlen(fname)+1;	/* (length of SMB_QUERY_FILE_UNIX_BASIC = 100)+4+4+strlen(fname)*/
							/* +1 to be sure to transmit the termination of fname */
			len = (len + 3) & ~3;

			SIVAL(p,0,len); p+= 4;       /* Offset from this structure to the beginning of the next one */
			SIVAL(p,0,reskey); p+= 4;    /* Used for continuing search. */

			/* Begin of SMB_QUERY_FILE_UNIX_BASIC */
			SOFF_T(p,0,get_file_size(sbuf));             /* File size 64 Bit */
			p+= 8;

			SOFF_T(p,0,get_allocation_size(NULL,&sbuf)); /* Number of bytes used on disk - 64 Bit */
			p+= 8;

			put_long_date(p,sbuf.st_ctime);       /* Creation Time 64 Bit */
			put_long_date(p+8,sbuf.st_atime);     /* Last access time 64 Bit */
			put_long_date(p+16,sbuf.st_mtime);    /* Last modification time 64 Bit */
			p+= 24;

			SIVAL(p,0,sbuf.st_uid);               /* user id for the owner */
			SIVAL(p,4,0);
			p+= 8;

			SIVAL(p,0,sbuf.st_gid);               /* group id of owner */
			SIVAL(p,4,0);
			p+= 8;

			SIVAL(p,0,unix_filetype(sbuf.st_mode));
			p+= 4;

			SIVAL(p,0,unix_dev_major(sbuf.st_rdev));   /* Major device number if type is device */
			SIVAL(p,4,0);
			p+= 8;

			SIVAL(p,0,unix_dev_minor(sbuf.st_rdev));   /* Minor device number if type is device */
			SIVAL(p,4,0);
			p+= 8;

			SINO_T(p,0,(SMB_INO_T)sbuf.st_ino);   /* inode number */
			p+= 8;

			SIVAL(p,0, unix_perms_to_wire(sbuf.st_mode));     /* Standard UNIX file permissions */
			SIVAL(p,4,0);
			p+= 8;

			SIVAL(p,0,sbuf.st_nlink);             /* number of hard links */
			SIVAL(p,4,0);
			p+= 8;

			/* End of SMB_QUERY_FILE_UNIX_BASIC */
			pstrcpy(p,fname);
			p=pdata+len;

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

static int call_trans2findfirst(connection_struct *conn, char *inbuf, char *outbuf, int bufsize,  
			char **pparams, int total_params, char **ppdata, int total_data)
{
	/* We must be careful here that we don't return more than the
		allowed number of data bytes. If this means returning fewer than
		maxentries then so be it. We assume that the redirector has
		enough room for the fixed number of parameter bytes it has
		requested. */
	uint32 max_data_bytes = SVAL(inbuf, smb_mdrcnt);
	char *params = *pparams;
	char *pdata = *ppdata;
	int dirtype;
	int maxentries;
	BOOL close_after_first;
	BOOL close_if_end;
	BOOL requires_resume_key;
	int info_level;
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

	if (total_params < 12)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	*directory = *mask = 0;

	dirtype = SVAL(params,0);
	maxentries = SVAL(params,2);
	close_after_first = BITSETW(params+4,0);
	close_if_end = BITSETW(params+4,1);
	requires_resume_key = BITSETW(params+4,2);
	info_level = SVAL(params,6);

	DEBUG(3,("call_trans2findfirst: dirtype = %d, maxentries = %d, close_after_first=%d, \
close_if_end = %d requires_resume_key = %d level = %d, max_data_bytes = %d\n",
		dirtype, maxentries, close_after_first, close_if_end, requires_resume_key,
		info_level, max_data_bytes));
  
	switch (info_level) {
		case 1:
		case 2:
		case 3:
		case 4:
		case SMB_FIND_FILE_DIRECTORY_INFO:
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		case SMB_FIND_FILE_NAMES_INFO:
		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
			break;
		case SMB_FIND_FILE_UNIX:
			if (!lp_unix_extensions())
				return(ERROR_DOS(ERRDOS,ERRunknownlevel));
			break;
		default:
			return(ERROR_DOS(ERRDOS,ERRunknownlevel));
	}

	pstrcpy(directory, params + 12); /* Complete directory path with wildcard mask appended */

	RESOLVE_FINDFIRST_DFSPATH(directory, conn, inbuf, outbuf);

	DEBUG(5,("path=%s\n",directory));

	unix_convert(directory,conn,0,&bad_path,&sbuf);
	if(!check_name(directory,conn)) {
		set_bad_path_error(errno, bad_path);

#if 0
		/* Ugly - NT specific hack - maybe not needed ? (JRA) */
		if((errno == ENOTDIR) && (Protocol >= PROTOCOL_NT1) && (get_remote_arch() == RA_WINNT)) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbaddirectory;
		}
#endif 

		return(UNIXERROR(ERRDOS,ERRbadpath));
	}

	p = strrchr(directory,'/');
	if(p == NULL) {
		/* Windows and OS/2 systems treat search on the root '\' as if it were '\*' */
		if((directory[0] == '.') && (directory[1] == '\0'))
			pstrcpy(mask,"*");
		else
			pstrcpy(mask,directory);
		pstrcpy(directory,"./");
	} else {
		pstrcpy(mask,p+1);
		*p = 0;
	}

	DEBUG(5,("dir=%s, mask = %s\n",directory, mask));

	pdata = Realloc(*ppdata, max_data_bytes + 1024);
	if( pdata == NULL )
		return(ERROR_DOS(ERRDOS,ERRnomem));
	*ppdata = pdata;
	memset((char *)pdata,'\0',max_data_bytes + 1024);

	/* Realloc the params space */
	params = Realloc(*pparams, 10);
	if( params == NULL )
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

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
  
	DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n", conn->dirpath,lp_dontdescend(SNUM(conn))));

	if (in_list(conn->dirpath,lp_dontdescend(SNUM(conn)),case_sensitive))
		dont_descend = True;
    
	p = pdata;
	space_remaining = max_data_bytes;
	out_of_space = False;

	for (i=0;(i<maxentries) && !finished && !out_of_space;i++) {
		BOOL got_exact_match = False;

		/* this is a heuristic to avoid seeking the dirptr except when 
			absolutely necessary. It allows for a filename of about 40 chars */

		if (space_remaining < DIRLEN_GUESS && numentries > 0) {
			out_of_space = True;
			finished = False;
		} else {
			finished = !get_lanman2_dir_entry(conn,mask,dirtype,info_level,
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

	if(close_after_first || (finished && close_if_end)) {
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

	if(!mangle_is_8_3_wildcards( mask, False))
		mangle_map(mask, True, True, SNUM(conn));

	return(-1);
}

/****************************************************************************
 Reply to a TRANS2_FINDNEXT.
****************************************************************************/

static int call_trans2findnext(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	/* We must be careful here that we don't return more than the
		allowed number of data bytes. If this means returning fewer than
		maxentries then so be it. We assume that the redirector has
		enough room for the fixed number of parameter bytes it has
		requested. */
	int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
	char *params = *pparams;
	char *pdata = *ppdata;
	int dptr_num;
	int maxentries;
	uint16 info_level;
	uint32 resume_key;
	BOOL close_after_request;
	BOOL close_if_end;
	BOOL requires_resume_key;
	BOOL continue_bit;
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

	if (total_params < 12)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	dptr_num = SVAL(params,0);
	maxentries = SVAL(params,2);
	info_level = SVAL(params,4);
	resume_key = IVAL(params,6);
	close_after_request = BITSETW(params+10,0);
	close_if_end = BITSETW(params+10,1);
	requires_resume_key = BITSETW(params+10,2);
	continue_bit = BITSETW(params+10,3);

	*mask = *directory = *resume_name = 0;

	pstrcpy( resume_name, params+12);

	DEBUG(3,("call_trans2findnext: dirhandle = %d, max_data_bytes = %d, maxentries = %d, \
close_after_request=%d, close_if_end = %d requires_resume_key = %d \
resume_key = %d resume name = %s continue=%d level = %d\n",
		dptr_num, max_data_bytes, maxentries, close_after_request, close_if_end, 
		requires_resume_key, resume_key, resume_name, continue_bit, info_level));

	switch (info_level) {
		case 1:
		case 2:
		case 3:
		case 4:
		case SMB_FIND_FILE_DIRECTORY_INFO:
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		case SMB_FIND_FILE_NAMES_INFO:
		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
			break;
		case SMB_FIND_FILE_UNIX:
			if (!lp_unix_extensions())
				return(ERROR_DOS(ERRDOS,ERRunknownlevel));
			break;
		default:
			return ERROR_DOS(ERRDOS,ERRunknownlevel);
	}

	pdata = Realloc( *ppdata, max_data_bytes + 1024);
	if(pdata == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);

	*ppdata	= pdata;
	memset((char *)pdata,'\0',max_data_bytes + 1024);

	/* Realloc the params space */
	params = Realloc(*pparams, 6*SIZEOFWORD);
	if( params == NULL )
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

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
		dptr_num, mask, dirtype, (long)conn->dirptr, TellDir(conn->dirptr)));

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

	if(requires_resume_key && *resume_name && !continue_bit) {

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

		for(current_pos = start_pos; current_pos >= 0; current_pos--) {
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
				mangle_map( dname, False, True, SNUM(conn));

			if(dname && strcsequal( resume_name, dname)) {
				SeekDir(dirptr, current_pos+1);
				DEBUG(7,("call_trans2findnext: got match at pos %d\n", current_pos+1 ));
				break;
			}
		}

		/*
		 * Scan forward from start if not found going backwards.
		 */

		if(current_pos < 0) {
			DEBUG(7,("call_trans2findnext: notfound: seeking to pos %d\n", start_pos));
			SeekDir(dirptr, start_pos);
			for(current_pos = start_pos; (dname = ReadDirName(dirptr)) != NULL; SeekDir(dirptr,++current_pos)) {

				/*
				 * Remember, name_map_mangle is called by
				 * get_lanman2_dir_entry(), so the resume name
				 * could be mangled. Ensure we do the same
				 * here.
				 */

				if(dname != NULL)
					mangle_map( dname, False, True, SNUM(conn));

				if(dname && strcsequal( resume_name, dname)) {
					SeekDir(dirptr, current_pos+1);
					DEBUG(7,("call_trans2findnext: got match at pos %d\n", current_pos+1 ));
					break;
				}
			} /* end for */
		} /* end if current_pos */
	} /* end if requires_resume_key && !continue_bit */

	for (i=0;(i<(int)maxentries) && !finished && !out_of_space ;i++) {
		BOOL got_exact_match = False;

		/* this is a heuristic to avoid seeking the dirptr except when 
			absolutely necessary. It allows for a filename of about 40 chars */

		if (space_remaining < DIRLEN_GUESS && numentries > 0) {
			out_of_space = True;
			finished = False;
		} else {
			finished = !get_lanman2_dir_entry(conn,mask,dirtype,info_level,
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
	if(close_after_request || (finished && close_if_end)) {
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

static int call_trans2qfsinfo(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
	char *pdata = *ppdata;
	char *params = *pparams;
	uint16 info_level;
	int data_len;
	SMB_STRUCT_STAT st;
	char *vname = volume_label(SNUM(conn));
	int snum = SNUM(conn);
	char *fstype = lp_fstype(SNUM(conn));

	if (total_params < 2)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	info_level = SVAL(params,0);
	DEBUG(3,("call_trans2qfsinfo: level = %d\n", info_level));

	if(vfs_stat(conn,".",&st)!=0) {
		DEBUG(2,("call_trans2qfsinfo: stat of . failed (%s)\n", strerror(errno)));
		return ERROR_DOS(ERRSRV,ERRinvdevice);
	}

	pdata = Realloc(*ppdata, max_data_bytes + 1024);
	if ( pdata == NULL )
		return ERROR_DOS(ERRDOS,ERRnomem);

	*ppdata = pdata;
	memset((char *)pdata,'\0',max_data_bytes + 1024);

	switch (info_level) {
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
		{ 
			/* Return volume name */
			int volname_len = MIN(strlen(vname),11);
			data_len = l2_vol_szVolLabel + volname_len + 1;
			/* 
			 * Add volume serial number - hash of a combination of
			 * the called hostname and the service name.
			 */
			SIVAL(pdata,0,str_checksum(lp_servicename(snum)) ^ (str_checksum(local_machine)<<16) );
			SCVAL(pdata,l2_vol_cch,volname_len);
			StrnCpy(pdata+l2_vol_szVolLabel,vname,volname_len);
			DEBUG(5,("call_trans2qfsinfo : time = %x, namelen = %d, name = %s\n",
				(unsigned)st.st_ctime, volname_len,
				pdata+l2_vol_szVolLabel));
			break;
		}

		case SMB_QUERY_FS_ATTRIBUTE_INFO:
		case SMB_FS_ATTRIBUTE_INFORMATION:
		{
			int fstype_len;
			SIVAL(pdata,0,FILE_CASE_PRESERVED_NAMES|FILE_CASE_SENSITIVE_SEARCH|
				(lp_nt_acl_support(SNUM(conn)) ? FILE_PERSISTENT_ACLS : 0)); /* FS ATTRIBUTES */
#if 0 /* Old code. JRA. */
			SIVAL(pdata,0,0x4006); /* FS ATTRIBUTES == long filenames supported? */
			SIVAL(pdata,0,0x700FF);
#endif /* Old code. */

			SIVAL(pdata,4,255); /* Max filename component length */
			/* NOTE! the fstype must *not* be null terminated or win98 won't recognise it
				and will think we can't do long filenames */
			fstype_len = dos_PutUniCode(pdata+12,unix_to_dos_static(fstype),sizeof(pstring), False);
			SIVAL(pdata,8,fstype_len);
			data_len = 12 + fstype_len;
			SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
			break;
		}

		case SMB_QUERY_FS_LABEL_INFO:
		case SMB_FS_LABEL_INFORMATION:
			data_len = 4 + strlen(vname);
			SIVAL(pdata,0,strlen(vname));
			pstrcpy(pdata+4,vname);      
			break;

		case SMB_QUERY_FS_VOLUME_INFO:      
		case SMB_FS_VOLUME_INFORMATION:
			/* 
			 * Add volume serial number - hash of a combination of
			 * the called hostname and the service name.
			 */
			SIVAL(pdata,8,str_checksum(lp_servicename(snum)) ^ 
				(str_checksum(local_machine)<<16));

			/* NT4 always serves this up as unicode but expects it to be
			 * delivered as ascii! (tridge && JRA)
			 */
			if ((get_remote_arch() != RA_WIN2K) && (global_client_caps & CAP_NT_SMBS)) {
				data_len = 18 + strlen(vname);
				SIVAL(pdata,12,strlen(vname));
				pstrcpy(pdata+18,vname);      
			} else {
				int vnamelen;

				vnamelen = dos_PutUniCode(pdata+18, vname, sizeof(pstring), False);
				data_len = 18 + vnamelen;
				SIVAL(pdata,12,vnamelen);
				SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
			}

			DEBUG(5,("call_trans2qfsinfo : SMB_QUERY_FS_VOLUME_INFO namelen = %d, vol = %s\n", 
				(int)strlen(vname),vname));
			break;

		case SMB_QUERY_FS_SIZE_INFO:
		case SMB_FS_SIZE_INFORMATION:
		{
			SMB_BIG_UINT dfree,dsize,bsize,block_size,sectors_per_unit,bytes_per_sector;
			data_len = 24;
			conn->vfs_ops.disk_free(conn,".",False,&bsize,&dfree,&dsize);	
			block_size = lp_block_size(snum);
			if (bsize < block_size) {
				SMB_BIG_UINT factor = block_size/bsize;
				bsize = block_size;
				dsize /= factor;
				dfree /= factor;
			}
			if (bsize > block_size) {
				SMB_BIG_UINT factor = bsize/block_size;
				bsize = block_size;
				dsize *= factor;
				dfree *= factor;
			}
			bytes_per_sector = 512;
			sectors_per_unit = bsize/bytes_per_sector;
			DEBUG(5,("call_trans2qfsinfo : SMB_QUERY_FS_SIZE_INFO bsize=%u, cSectorUnit=%u, \
cBytesSector=%u, cUnitTotal=%u, cUnitAvail=%d\n", (unsigned int)bsize, (unsigned int)sectors_per_unit,
				(unsigned int)bytes_per_sector, (unsigned int)dsize, (unsigned int)dfree));
			SBIG_UINT(pdata,0,dsize);
			SBIG_UINT(pdata,8,dfree);
			SIVAL(pdata,16,sectors_per_unit);
			SIVAL(pdata,20,bytes_per_sector);
			break;
		}

		case SMB_FS_FULL_SIZE_INFORMATION:
		{
			SMB_BIG_UINT dfree,dsize,bsize,block_size,sectors_per_unit,bytes_per_sector;
			data_len = 32;
			conn->vfs_ops.disk_free(conn,".",False,&bsize,&dfree,&dsize);	
			block_size = lp_block_size(snum);
			if (bsize < block_size) {
				SMB_BIG_UINT factor = block_size/bsize;
				bsize = block_size;
				dsize /= factor;
				dfree /= factor;
			}
			if (bsize > block_size) {
				SMB_BIG_UINT factor = bsize/block_size;
				bsize = block_size;
				dsize *= factor;
				dfree *= factor;
			}
			bytes_per_sector = 512;
			sectors_per_unit = bsize/bytes_per_sector;
			DEBUG(5,("call_trans2qfsinfo : SMB_QUERY_FS_FULL_SIZE_INFO bsize=%u, cSectorUnit=%u, \
cBytesSector=%u, cUnitTotal=%u, cUnitAvail=%d\n", (unsigned int)bsize, (unsigned int)sectors_per_unit,
				(unsigned int)bytes_per_sector, (unsigned int)dsize, (unsigned int)dfree));
			SBIG_UINT(pdata,0,dsize); /* Total Allocation units. */
			SBIG_UINT(pdata,8,dfree); /* Caller available allocation units. */
			SBIG_UINT(pdata,16,dfree); /* Actual available allocation units. */
			SIVAL(pdata,24,sectors_per_unit); /* Sectors per allocation unit. */
			SIVAL(pdata,28,bytes_per_sector); /* Bytes per sector. */
			break;
		}

		case SMB_QUERY_FS_DEVICE_INFO:
		case SMB_FS_DEVICE_INFORMATION:
			data_len = 8;
			SIVAL(pdata,0,0); /* dev type */
			SIVAL(pdata,4,0); /* characteristics */
			break;

		case SMB_FS_OBJECTID_INFORMATION:
			data_len = 64;
			break;

		/*
		 * Query the version and capabilities of the CIFS UNIX extensions
		 * in use.
		 */

		case SMB_QUERY_CIFS_UNIX_INFO:

			if (!lp_unix_extensions())
				return ERROR_DOS(ERRDOS,ERRunknownlevel);

			data_len = 12;
			SSVAL(pdata,0,CIFS_UNIX_MAJOR_VERSION);
			SSVAL(pdata,2,CIFS_UNIX_MINOR_VERSION);
			SBIG_UINT(pdata,4,((SMB_BIG_UINT)0)); /* No capabilities for now... */
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

	DEBUG( 4, ( "%s info_level = %d\n", smb_fn_name(CVAL(inbuf,smb_com)), info_level) );

	return -1;
}

/****************************************************************************
 Reply to a TRANS2_SETFSINFO (set filesystem info).
****************************************************************************/

static int call_trans2setfsinfo(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	/* Just say yes we did it - there is nothing that
		can be set here so it doesn't matter. */
	int outsize;
	DEBUG(3,("call_trans2setfsinfo\n"));

	if (!CAN_WRITE(conn))
		return(ERROR_DOS(ERRSRV,ERRaccess));

	outsize = set_message(outbuf,10,0,True);

	return outsize;
}

/****************************************************************************
 Utility function to set bad path error.
****************************************************************************/

NTSTATUS set_bad_path_error(int err, BOOL bad_path)
{
	if((err == ENOENT) && bad_path) {
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRbadpath;
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
  Reply to a TRANS2_QFILEPATHINFO or TRANSACT2_QFILEINFO (query file info by
  file name or file id).
****************************************************************************/

static int call_trans2qfilepathinfo(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
	char *params = *pparams;
	char *pdata = *ppdata;
	uint16 tran_call = SVAL(inbuf, smb_setup0);
	uint16 info_level;
	int mode=0;
	SMB_OFF_T size=0;
	SMB_BIG_UINT allocation_size = 0;
	unsigned int data_size;
	SMB_STRUCT_STAT sbuf;
	pstring fname1;
	char *fname;
	pstring dos_fname;
	char *fullpathname;
	char *p;
	int l;
	SMB_OFF_T pos = 0;
	BOOL bad_path = False;
	BOOL delete_pending = False;
	time_t c_time;
	files_struct *fsp = NULL;

	if (!params)
		return ERROR_NT(NT_STATUS_INVALID_PARAMETER);

	if (tran_call == TRANSACT2_QFILEINFO) {
		if (total_params < 4)
			return(ERROR_DOS(ERRDOS,ERRinvalidparam));

		fsp = file_fsp(params,0);
		info_level = SVAL(params,2);

		DEBUG(3,("call_trans2qfilepathinfo: TRANSACT2_QFILEINFO: level = %d\n", info_level));

		if(fsp && (fsp->is_directory || fsp->fd == -1)) {
			/*
			 * This is actually a QFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			fname = fsp->fsp_name;
			unix_convert(fname,conn,0,&bad_path,&sbuf);
			if (!check_name(fname,conn)) {
				DEBUG(3,("call_trans2qfilepathinfo: check_name of %s failed (%s)\n",fname,strerror(errno)));
				set_bad_path_error(errno, bad_path);
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}

			if (INFO_LEVEL_IS_UNIX(info_level)) {
				/* Always do lstat for UNIX calls. */
				if (vfs_lstat(conn,fname,&sbuf)) {
					DEBUG(3,("call_trans2qfilepathinfo: vfs_lstat of %s failed (%s)\n",fname,strerror(errno)));
					set_bad_path_error(errno, bad_path);
					return(UNIXERROR(ERRDOS,ERRbadpath));
				}
			} else if (!VALID_STAT(sbuf) && vfs_stat(conn,fname,&sbuf)) {
				DEBUG(3,("call_trans2qfilepathinfo: vfs_stat of %s failed (%s)\n",fname,strerror(errno)));
				set_bad_path_error(errno, bad_path);
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}

			delete_pending = fsp->directory_delete_on_close;

		} else {
			/*
			 * Original code - this is an open file.
			 */
			CHECK_FSP(fsp,conn);

			fname = fsp->fsp_name;
			if (vfs_fstat(fsp,fsp->fd,&sbuf) != 0) {
				DEBUG(3,("fstat of fnum %d failed (%s)\n",fsp->fnum, strerror(errno)));
				return(UNIXERROR(ERRDOS,ERRbadfid));
			}

			if((pos = fsp->conn->vfs_ops.lseek(fsp,fsp->fd,0,SEEK_CUR)) == -1)
				return(UNIXERROR(ERRDOS,ERRnoaccess));

			delete_pending = fsp->delete_on_close;
		}
	} else {
		/* qpathinfo */
		if (total_params < 6)
			return(ERROR_DOS(ERRDOS,ERRinvalidparam));

		info_level = SVAL(params,0);

		DEBUG(3,("call_trans2qfilepathinfo: TRANSACT2_QPATHINFO: level = %d\n", info_level));

		fname = &fname1[0];
		pstrcpy(fname,&params[6]);

		RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

		unix_convert(fname,conn,0,&bad_path,&sbuf);
		if (!check_name(fname,conn)) {
			DEBUG(3,("call_trans2qfilepathinfo: check_name of %s failed (%s)\n",fname,strerror(errno)));
			set_bad_path_error(errno, bad_path);
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}
		if (INFO_LEVEL_IS_UNIX(info_level)) {
			/* Always do lstat for UNIX calls. */
			if (vfs_lstat(conn,fname,&sbuf)) {
				DEBUG(3,("call_trans2qfilepathinfo: vfs_lstat of %s failed (%s)\n",fname,strerror(errno)));
				set_bad_path_error(errno, bad_path);
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}
		} else if (!VALID_STAT(sbuf) && vfs_stat(conn,fname,&sbuf)) {
			DEBUG(3,("call_trans2qfilepathinfo: vfs_stat of %s failed (%s)\n",fname,strerror(errno)));
			set_bad_path_error(errno, bad_path);
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}
	}


	if (INFO_LEVEL_IS_UNIX(info_level) && !lp_unix_extensions())
		return ERROR_DOS(ERRDOS,ERRunknownlevel);

	DEBUG(3,("call_trans2qfilepathinfo %s level=%d call=%d total_data=%d\n",
			fname,info_level,tran_call,total_data));

	p = strrchr(fname,'/'); 
	if (!p) 
		p = fname;
	else
		p++;
	l = strlen(p);  
	mode = dos_mode(conn,fname,&sbuf);
	fullpathname = fname;
	size = get_file_size(sbuf);
	allocation_size = get_allocation_size(fsp,&sbuf);
	if (mode & aDIR)
		size = 0;

	/* from now on we only want the part after the / */
	fname = p;
  
	params = Realloc(*pparams,2);
	if ( params == NULL )
	  return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams	= params;
	memset((char *)params,'\0',2);
	data_size = max_data_bytes + 1024;
	pdata = Realloc(*ppdata, data_size); 
	if ( pdata == NULL )
		return ERROR_DOS(ERRDOS,ERRnomem);
	*ppdata	= pdata;

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

        /* NT expects the name to be in an exact form */
	if (strequal(fname,"."))
		pstrcpy(dos_fname, "\\");
	else {
		snprintf(dos_fname, sizeof(dos_fname), "\\%s", fname);
		string_replace( dos_fname, '/','\\');
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
		SCVAL(pdata,20,0);
		SCVAL(pdata,21,(mode&aDIR)?1:0);
		break;

	case SMB_FILE_EA_INFORMATION:
	case SMB_QUERY_FILE_EA_INFO:
		data_size = 4;
		SIVAL(pdata,0,0);
		break;

		/* Get the 8.3 name - used if NT SMB was negotiated. */

	case SMB_QUERY_FILE_ALT_NAME_INFO:
	{
		pstring short_name;
		pstrcpy(short_name,p);
		/* Mangle if not already 8.3 */
		if(!mangle_is_8_3(short_name, True)) {
			mangle_map(short_name,True,True,SNUM(conn));
		}
		strupper(short_name);
		SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
		l = dos_PutUniCode(pdata + 4, short_name, sizeof(pstring), False);
		data_size = 4 + l;
		SIVAL(pdata,0,l);
		break;
	}

	case SMB_QUERY_FILE_NAME_INFO:
		/*
		 * The first part of this code is essential
		 * to get security descriptors to work on mapped
		 * drives. Don't ask how I discovered this unless
		 * you like hearing about me suffering.... :-). JRA.
		 */

		SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
		l = dos_PutUniCode(pdata + 4, dos_fname,sizeof(pstring), False);
		data_size = 4 + l;
		SIVAL(pdata,0,l);
		break;

	case SMB_FILE_ALLOCATION_INFORMATION:
	case SMB_QUERY_FILE_ALLOCATION_INFO:
		data_size = 8;
		SOFF_T(pdata,0,allocation_size);
		break;

	case SMB_QUERY_FILE_END_OF_FILEINFO:
	case SMB_FILE_END_OF_FILE_INFORMATION:
		data_size = 8;
		SOFF_T(pdata,0,size);
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
		SCVAL(pdata,20,delete_pending);
		SCVAL(pdata,21,(mode&aDIR)?1:0);
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
		SIVAL(pdata,0,l);
		pstrcpy(pdata+4,dos_fname);
		pdata += 4 + l;
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
			size_t byte_len;

			SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
			byte_len = dos_PutUniCode(pdata+4,dos_fname,max_data_bytes,False);
			SIVAL(pdata,0,byte_len);
			data_size = 4 + byte_len;
			break;
		}

	case SMB_FILE_DISPOSITION_INFORMATION:
		data_size = 1;
		SCVAL(pdata,0,delete_pending);
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
			size_t byte_len = dos_PutUniCode(pdata+4,dos_fname,max_data_bytes,False);
			SIVAL(pdata,0,byte_len);
			data_size = 4 + byte_len;
			break;
		}
		
#if 0
	/*
	 * NT4 server just returns "invalid query" to this - if we try to answer 
	 * it then NTws gets a BSOD! (tridge).
	 * W2K seems to want this. JRA.
	 */ 
	case SMB_QUERY_FILE_STREAM_INFO:
#endif
	case SMB_FILE_STREAM_INFORMATION:
		if (mode & aDIR) {
			data_size = 0;
		} else {
			size_t byte_len = dos_PutUniCode(pdata+24,"::$DATA", 14, False);
			SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2)|FLAGS2_UNICODE_STRINGS);
			SIVAL(pdata,0,0); /* Next stream (none). */
			SIVAL(pdata,4,byte_len); /* Byte length of unicode string ::$DATA */
			SOFF_T(pdata,8,size);
			SOFF_T(pdata,16,allocation_size);
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
		SOFF_T(pdata,32,allocation_size); /* Allocation size. */
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

	/*
	 * CIFS UNIX Extensions.
	 */

	case SMB_QUERY_FILE_UNIX_BASIC:

		DEBUG(4,("call_trans2qfilepathinfo: st_mode=%o\n",(int)sbuf.st_mode));

		SOFF_T(pdata,0,get_file_size(sbuf));             /* File size 64 Bit */
		pdata += 8;

		SOFF_T(pdata,0,get_allocation_size(fsp,&sbuf)); /* Number of bytes used on disk - 64 Bit */
		pdata += 8;

		put_long_date(pdata,sbuf.st_ctime);       /* Creation Time 64 Bit */
		put_long_date(pdata+8,sbuf.st_atime);     /* Last access time 64 Bit */
		put_long_date(pdata+16,sbuf.st_mtime);    /* Last modification time 64 Bit */
		pdata += 24;

		SIVAL(pdata,0,sbuf.st_uid);               /* user id for the owner */
		SIVAL(pdata,4,0);
		pdata += 8;

		SIVAL(pdata,0,sbuf.st_gid);               /* group id of owner */
		SIVAL(pdata,4,0);
		pdata += 8;

		SIVAL(pdata,0,unix_filetype(sbuf.st_mode));
		pdata += 4;

		SIVAL(pdata,0,unix_dev_major(sbuf.st_rdev));   /* Major device number if type is device */
		SIVAL(pdata,4,0);
		pdata += 8;

		SIVAL(pdata,0,unix_dev_minor(sbuf.st_rdev));   /* Minor device number if type is device */
		SIVAL(pdata,4,0);
		pdata += 8;

		SINO_T(pdata,0,(SMB_INO_T)sbuf.st_ino);   /* inode number */
		pdata += 8;

		SIVAL(pdata,0, unix_perms_to_wire(sbuf.st_mode));     /* Standard UNIX file permissions */
		SIVAL(pdata,4,0);
		pdata += 8;

		SIVAL(pdata,0,sbuf.st_nlink);             /* number of hard links */
		SIVAL(pdata,4,0);
		pdata += 8+1;
		data_size = PTR_DIFF(pdata,(*ppdata));

		{
			int i;
			DEBUG(4,("call_trans2qfilepathinfo: SMB_QUERY_FILE_UNIX_BASIC"));

			for (i=0; i<100; i++)
				DEBUG(4,("%d=%x, ",i, (*ppdata)[i]));
			DEBUG(4,("\n"));
		}

		break;

	case SMB_QUERY_FILE_UNIX_LINK:
		{
			pstring buffer;
			int len;

#ifdef S_ISLNK
			if(!S_ISLNK(sbuf.st_mode))
				return(UNIXERROR(ERRSRV,ERRbadlink));
#else
			return(UNIXERROR(ERRDOS,ERRbadlink));
#endif
			len = conn->vfs_ops.readlink(conn,dos_to_unix_static(fullpathname), buffer, sizeof(pstring)-1);     /* read link */
			if (len == -1)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
			buffer[len] = 0;
			unix_to_dos(buffer);
			pstrcpy(pdata,buffer);                            /* write '\0' terminated string */
			pdata += strlen(buffer)+1;
			data_size = PTR_DIFF(pdata,(*ppdata));

			break;
		}

	default:
			return ERROR_DOS(ERRDOS,ERRunknownlevel);
	}

	send_trans2_replies( outbuf, bufsize, params, 2, *ppdata, data_size);

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

	if (delete_on_close && !(fsp->desired_access & DELETE_ACCESS)) {
		DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but delete access denied.\n",
				fsp->fsp_name ));
		return NT_STATUS_ACCESS_DENIED;
	}

	if(fsp->is_directory) {
		fsp->directory_delete_on_close = delete_on_close;
		DEBUG(10, ("set_delete_on_close_internal: %s delete on close flag for fnum = %d, directory %s\n",
			delete_on_close ? "Added" : "Removed", fsp->fnum, fsp->fsp_name ));
	} else {
		fsp->delete_on_close = delete_on_close;
		DEBUG(10, ("set_delete_on_close_internal: %s delete on close flag for fnum = %d, file %s\n",
			delete_on_close ? "Added" : "Removed", fsp->fnum, fsp->fsp_name ));
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Sets the delete on close flag over all share modes on this file.
 Modify the share mode entry for all files open
 on this device and inode to tell other smbds we have 
 changed the delete on close flag. This will be noticed
 in the close code, the last closer will delete the file
 if flag is set.
****************************************************************************/

NTSTATUS set_delete_on_close_over_all(files_struct *fsp, BOOL delete_on_close)
{
	DEBUG(10,("set_delete_on_close_over_all: %s delete on close flag for fnum = %d, file %s\n",
		delete_on_close ? "Adding" : "Removing", fsp->fnum, fsp->fsp_name ));

	if (lock_share_entry_fsp(fsp) == False)
		return NT_STATUS_ACCESS_DENIED;

	if (!modify_delete_flag(fsp->dev, fsp->inode, delete_on_close)) {
		DEBUG(0,("set_delete_on_close_internal: failed to change delete on close flag for file %s\n",
			fsp->fsp_name ));
		unlock_share_entry_fsp(fsp);
		return NT_STATUS_ACCESS_DENIED;
	}

	unlock_share_entry_fsp(fsp);
	return NT_STATUS_OK;
}

/****************************************************************************
 Returns true if this pathname is within the share, and thus safe.
****************************************************************************/

static int ensure_link_is_safe(connection_struct *conn, const char *link_dest_in, char *link_dest_out)
{
#ifdef PATH_MAX
	char resolved_name[PATH_MAX+1];
#else
	pstring resolved_name;
#endif
	fstring last_component;
	pstring link_dest;
	pstring link_test;
	char *p;
	BOOL bad_path = False;
	SMB_STRUCT_STAT sbuf;

	pstrcpy(link_dest, link_dest_in);
	unix_convert(link_dest,conn,0,&bad_path,&sbuf);

	/* Store the UNIX converted path. */
	pstrcpy(link_dest_out, link_dest);

	p = strrchr(link_dest, '/');
	if (p) {
		fstrcpy(last_component, p+1);
		*p = '\0';
	} else {
		fstrcpy(last_component, link_dest);
		pstrcpy(link_dest, "./");
	}
		
	if (conn->vfs_ops.realpath(conn,dos_to_unix_static(link_dest),resolved_name) == NULL)
		return -1;

	pstrcpy(link_dest, unix_to_dos_static(resolved_name));
	pstrcat(link_dest, "/");
	pstrcat(link_dest, last_component);

	if (*link_dest != '/') {
		/* Relative path. */
		pstrcpy(link_test, conn->connectpath);
		pstrcat(link_test, "/");
		pstrcat(link_test, link_dest);
	} else {
		pstrcpy(link_test, link_dest);
	}

	/*
	 * Check if the link is within the share.
	 */

	if (strncmp(conn->connectpath, link_test, strlen(conn->connectpath))) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

/****************************************************************************
 Reply to a TRANS2_SETFILEINFO (set file info by fileid).
****************************************************************************/

static int call_trans2setfilepathinfo(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *params = *pparams;
	char *pdata = *ppdata;
	uint16 tran_call = SVAL(inbuf, smb_setup0);
	uint16 info_level;
	int dosmode = 0;
	SMB_OFF_T size=0;
	struct utimbuf tvs;
	SMB_STRUCT_STAT sbuf;
	pstring fname1;
	char *fname = NULL;
	int fd = -1;
	BOOL bad_path = False;
	files_struct *fsp = NULL;
	uid_t set_owner = (uid_t)SMB_UID_NO_CHANGE;
	gid_t set_grp = (uid_t)SMB_GID_NO_CHANGE;
	mode_t unixmode = 0;

	if (tran_call == TRANSACT2_SETFILEINFO) {

		if (total_params < 4)
			return(ERROR_DOS(ERRDOS,ERRinvalidparam));

		fsp = file_fsp(params,0);
		info_level = SVAL(params,2);    

		if(fsp && (fsp->is_directory || fsp->fd == -1)) {
			/*
			 * This is actually a SETFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			fname = fsp->fsp_name;
			unix_convert(fname,conn,0,&bad_path,&sbuf);
			if (!check_name(fname,conn) || (!VALID_STAT(sbuf))) {
				DEBUG(3,("fileinfo of %s failed (%s)\n",fname,strerror(errno)));
				set_bad_path_error(errno, bad_path);
				return(UNIXERROR(ERRDOS,ERRbadpath));
			}
		} else if (fsp && fsp->print_file) {
			/*
			 * Doing a DELETE_ON_CLOSE should cancel a print job.
			 */
			if (((info_level == SMB_SET_FILE_DISPOSITION_INFO)||(info_level == SMB_FILE_DISPOSITION_INFORMATION)) &&
					CVAL(pdata,0)) {
				fsp->share_mode = FILE_DELETE_ON_CLOSE;

				DEBUG(3,("call_trans2setfilepathinfo: Cancelling print job (%s)\n",
					fsp->fsp_name ));

				SSVAL(params,0,0);
				send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
				return(-1);
			} else
				return(UNIXERROR(ERRDOS,ERRbadpath));
		} else {
			/*
			 * Original code - this is an open file.
			 */
			CHECK_FSP(fsp,conn);

			fname = fsp->fsp_name;
			fd = fsp->fd;

			if (vfs_fstat(fsp,fd,&sbuf) != 0) {
				DEBUG(3,("fstat of fnum %d failed (%s)\n",fsp->fnum, strerror(errno)));
				return(UNIXERROR(ERRDOS,ERRbadfid));
			}
		}
	} else {
		/* set path info */
		if (total_params < 6)
			return(ERROR_DOS(ERRDOS,ERRinvalidparam));

		info_level = SVAL(params,0);    
		fname = fname1;
		pstrcpy(fname,&params[6]);
		unix_convert(fname,conn,0,&bad_path,&sbuf);
		if(!check_name(fname, conn)) {
			set_bad_path_error(errno, bad_path);
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}

		/*
		 * For CIFS UNIX extensions the target name may not exist.
		 */

		if(!VALID_STAT(sbuf) && !INFO_LEVEL_IS_UNIX(info_level)) {

			DEBUG(3,("stat of %s failed (%s)\n", fname, strerror(errno)));
			set_bad_path_error(errno, bad_path);
			return(UNIXERROR(ERRDOS,ERRbadpath));
		}    
	}

	if (!CAN_WRITE(conn))
		return ERROR_DOS(ERRSRV,ERRaccess);

	if (INFO_LEVEL_IS_UNIX(info_level) && !lp_unix_extensions())
		return ERROR_DOS(ERRDOS,ERRunknownlevel);

	if (VALID_STAT(sbuf))
		unixmode = sbuf.st_mode;

	DEBUG(3,("call_trans2setfilepathinfo(%d) %s info_level=%d totdata=%d\n",
		tran_call,fname,info_level,total_data));

	/* Realloc the parameter and data sizes */
	params = Realloc(*pparams,2);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

	SSVAL(params,0,0);

	if (fsp) {
		/* the pending modtime overrides the current modtime */
		sbuf.st_mtime = fsp->pending_modtime;
	}

	size = get_file_size(sbuf);
	tvs.modtime = sbuf.st_mtime;
	tvs.actime = sbuf.st_atime;
	dosmode = dos_mode(conn,fname,&sbuf);
	unixmode = sbuf.st_mode;

	set_owner = VALID_STAT(sbuf) ? sbuf.st_uid : (uid_t)SMB_UID_NO_CHANGE;
	set_grp = VALID_STAT(sbuf) ? sbuf.st_gid : (gid_t)SMB_GID_NO_CHANGE;

	switch (info_level) {
		case SMB_INFO_STANDARD:
		{
			if (total_data < l1_cbFile+4)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			/* access time */
			tvs.actime = make_unix_date2(pdata+l1_fdateLastAccess);

			/* write time */
			tvs.modtime = make_unix_date2(pdata+l1_fdateLastWrite);

			dosmode = SVAL(pdata,l1_attrFile);
			size = IVAL(pdata,l1_cbFile);
			break;
		}

		case SMB_INFO_SET_EA:
			return(ERROR_DOS(ERRDOS,ERReasnotsupported));

		/* XXXX um, i don't think this is right.
		it's also not in the cifs6.txt spec.
		*/
		case SMB_INFO_QUERY_EAS_FROM_LIST:
			if (total_data < 28)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			tvs.actime = make_unix_date2(pdata+8);
			tvs.modtime = make_unix_date2(pdata+12);
			size = IVAL(pdata,16);
			dosmode = IVAL(pdata,24);
			break;

		/* XXXX nor this.  not in cifs6.txt, either. */
		case SMB_INFO_QUERY_ALL_EAS:
			if (total_data < 28)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			tvs.actime = make_unix_date2(pdata+8);
			tvs.modtime = make_unix_date2(pdata+12);
			size = IVAL(pdata,16);
			dosmode = IVAL(pdata,24);
			break;

		case SMB_SET_FILE_BASIC_INFO:
		case SMB_FILE_BASIC_INFORMATION:
		{
			/* Patch to do this correctly from Paul Eggert <eggert@twinsun.com>. */
			time_t write_time;
			time_t changed_time;

			if (total_data < 36)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			/* Ignore create time at offset pdata. */

			/* access time */
			tvs.actime = interpret_long_date(pdata+8);

			write_time = interpret_long_date(pdata+16);
			changed_time = interpret_long_date(pdata+24);

			tvs.modtime = MIN(write_time, changed_time);

			if (write_time > tvs.modtime && write_time != 0xffffffff) {
				tvs.modtime = write_time;
			}

			/* Prefer a defined time to an undefined one. */
			if (tvs.modtime == (time_t)0 || tvs.modtime == (time_t)-1)
				tvs.modtime = (write_time == (time_t)0 || write_time == (time_t)-1
							? changed_time
							: write_time);

			/* attributes */
			dosmode = IVAL(pdata,32);
			break;
		}

		case SMB_FILE_ALLOCATION_INFORMATION:
		case SMB_SET_FILE_ALLOCATION_INFO:
		{
			int ret = -1;
			SMB_BIG_UINT allocation_size;

			if (total_data < 8)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			allocation_size = (SMB_BIG_UINT)IVAL(pdata,0);
#ifdef LARGE_SMB_OFF_T
			allocation_size |= (((SMB_BIG_UINT)IVAL(pdata,4)) << 32);
#else /* LARGE_SMB_OFF_T */
			if (IVAL(pdata,4) != 0)	/* more than 32 bits? */
				return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif /* LARGE_SMB_OFF_T */
			DEBUG(10,("call_trans2setfilepathinfo: Set file allocation info for file %s to %.0f\n",
				fname, (double)allocation_size ));

			if (allocation_size)
				allocation_size = SMB_ROUNDUP(allocation_size,SMB_ROUNDUP_ALLOCATION_SIZE);

			if(allocation_size != get_file_size(sbuf)) {
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

					new_fsp = open_file_shared1(conn, fname, &sbuf,FILE_WRITE_DATA,
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
					ret = vfs_allocate_file_space(fsp, allocation_size);
					if (vfs_fstat(fsp,fd,&new_sbuf) != 0) {
						DEBUG(3,("fstat of fnum %d failed (%s)\n",fsp->fnum, strerror(errno)));
						ret = -1;
					}
				}
				if (ret == -1)
					return ERROR_NT(NT_STATUS_DISK_FULL);

				/* Allocate can trucate size... */
				size = get_file_size(new_sbuf);
			}

			break;
		}

		case SMB_FILE_END_OF_FILE_INFORMATION:
		case SMB_SET_FILE_END_OF_FILE_INFO:
		{
			if (total_data < 8)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

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
			BOOL delete_on_close;
			NTSTATUS status;

			if (total_data < 1)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			delete_on_close = (CVAL(pdata,0) ? True : False);

			if (tran_call != TRANSACT2_SETFILEINFO)
				return(ERROR_DOS(ERRDOS,ERRunknownlevel));

			if (fsp == NULL)
				return(UNIXERROR(ERRDOS,ERRbadfid));

			status = set_delete_on_close_internal(fsp, delete_on_close);
			if (NT_STATUS_V(status) !=  NT_STATUS_V(NT_STATUS_OK))
				return ERROR_NT(status);

			/* The set is across all open files on this dev/inode pair. */
			status =set_delete_on_close_over_all(fsp, delete_on_close);
			if (NT_STATUS_V(status) !=  NT_STATUS_V(NT_STATUS_OK))
				return ERROR_NT(status);

			break;
		}

		/*
		 * CIFS UNIX extensions.
		 */

		case SMB_SET_FILE_UNIX_BASIC:
		{
			uint32 raw_unixmode;

			if (total_data < 100)
				return(ERROR_DOS(ERRDOS,ERRinvalidparam));

			if(IVAL(pdata, 0) != SMB_SIZE_NO_CHANGE_LO &&
			   IVAL(pdata, 4) != SMB_SIZE_NO_CHANGE_HI) {
				size=IVAL(pdata,0); /* first 8 Bytes are size */
#ifdef LARGE_SMB_OFF_T
				size |= (((SMB_OFF_T)IVAL(pdata,4)) << 32);
#else /* LARGE_SMB_OFF_T */
				if (IVAL(pdata,4) != 0)	/* more than 32 bits? */
					return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif /* LARGE_SMB_OFF_T */
			}
			pdata+=24;          /* ctime & st_blocks are not changed */
			tvs.actime = interpret_long_unix_date(pdata); /* access_time */
			tvs.modtime = interpret_long_unix_date(pdata+8); /* modification_time */
			pdata+=16;
			set_owner = (uid_t)IVAL(pdata,0);
			pdata += 8;
			set_grp = (gid_t)IVAL(pdata,0);
			pdata += 8;
			raw_unixmode = IVAL(pdata,28);
			unixmode = unix_perms_from_wire(conn, &sbuf, raw_unixmode);
			dosmode = 0; /* Ensure dos mode change doesn't override this. */

			DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_BASIC: name = %s \
size = %.0f, uid = %u, gid = %u, raw perms = 0%o\n",
				fname, (double)size, (unsigned int)set_owner, (unsigned int)set_grp, (int)raw_unixmode));

			if (!VALID_STAT(sbuf)) {

				/*
				 * The only valid use of this is to create character and block
				 * devices, and named pipes. This is deprecated (IMHO) and 
				 * a new info level should be used for mknod. JRA.
				 */

#if !defined(HAVE_MAKEDEV_FN)
				return(ERROR_DOS(ERRDOS,ERRnoaccess));
#else /* HAVE_MAKEDEV_FN */
				uint32 file_type = IVAL(pdata,0);
				uint32 dev_major = IVAL(pdata,4);
				uint32 dev_minor = IVAL(pdata,12);

				uid_t myuid = geteuid();
				gid_t mygid = getegid();
				SMB_DEV_T dev;

				if (tran_call == TRANSACT2_SETFILEINFO)
					return(ERROR_DOS(ERRDOS,ERRnoaccess));

				if (raw_unixmode == SMB_MODE_NO_CHANGE)
					return(ERROR_DOS(ERRDOS,ERRinvalidparam));

				dev = makedev(dev_major, dev_minor);

				/* We can only create as the owner/group we are. */

				if ((set_owner != myuid) && (set_owner != (uid_t)SMB_UID_NO_CHANGE))
					return(ERROR_DOS(ERRDOS,ERRnoaccess));
				if ((set_grp != mygid) && (set_grp != (gid_t)SMB_GID_NO_CHANGE))
					return(ERROR_DOS(ERRDOS,ERRnoaccess));

				if (file_type != UNIX_TYPE_CHARDEV && file_type != UNIX_TYPE_BLKDEV &&
						file_type != UNIX_TYPE_FIFO)
					return(ERROR_DOS(ERRDOS,ERRnoaccess));

				DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_BASIC doing mknod dev %.0f mode \
0%o for file %s\n", (double)dev, unixmode, fname ));

				/* Ok - do the mknod. */
				if (conn->vfs_ops.mknod(conn,dos_to_unix_static(fname), unixmode, dev) != 0)
					return(UNIXERROR(ERRDOS,ERRnoaccess));

				SSVAL(params,0,0);
				send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
				return(-1);
#endif /* HAVE_MAKEDEV_FN */

			}

			/*
			 * Deal with the UNIX specific mode set.
			 */

			if (raw_unixmode != SMB_MODE_NO_CHANGE) {
				DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_BASIC setting mode 0%o for file %s\n",
					(unsigned int)unixmode, fname ));
				if (vfs_chmod(conn,fname,unixmode) != 0)
					return(UNIXERROR(ERRDOS,ERRnoaccess));
			}

			/*
			 * Deal with the UNIX specific uid set.
			 */

			if ((set_owner != (uid_t)SMB_UID_NO_CHANGE) && (sbuf.st_uid != set_owner)) {
				DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_BASIC changing owner %u for file %s\n",
					(unsigned int)set_owner, fname ));
				if (vfs_chown(conn,fname,set_owner, (gid_t)-1) != 0)
					return(UNIXERROR(ERRDOS,ERRnoaccess));
			}

			/*
			 * Deal with the UNIX specific gid set.
			 */

			if ((set_grp != (uid_t)SMB_GID_NO_CHANGE) && (sbuf.st_gid != set_grp)) {
				DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_BASIC changing group %u for file %s\n",
					(unsigned int)set_owner, fname ));
				if (vfs_chown(conn,fname,(uid_t)-1, set_grp) != 0)
					return(UNIXERROR(ERRDOS,ERRnoaccess));
			}
			break;
		}

		case SMB_SET_FILE_UNIX_LINK:
		{
			pstring link_dest;
			/* Set a symbolic link. */
			/* Don't allow this if follow links is false. */

			if (!lp_symlinks(SNUM(conn)))
				return(ERROR_DOS(ERRDOS,ERRnoaccess));

			/* Disallow if already exists. */
			if (VALID_STAT(sbuf))
				return(ERROR_DOS(ERRDOS,ERRbadpath));

			pstrcpy(link_dest, pdata);

			if (ensure_link_is_safe(conn, link_dest, link_dest) != 0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
			dos_to_unix(link_dest);
			dos_to_unix(fname);

			DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_LINK doing symlink %s -> %s\n",
				fname, link_dest ));

			if (conn->vfs_ops.symlink(conn,link_dest,fname) != 0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
			SSVAL(params,0,0);
			send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
			return(-1);
		}

		case SMB_SET_FILE_UNIX_HLINK:
		{
			pstring link_dest;

			/* Set a hard link. */

			/* Disallow if already exists. */
			if (VALID_STAT(sbuf))
				return(ERROR_DOS(ERRDOS,ERRbadpath));

			pstrcpy(link_dest, pdata);

			if (ensure_link_is_safe(conn, link_dest, link_dest) != 0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));

			dos_to_unix(link_dest);
			dos_to_unix(fname);

			DEBUG(10,("call_trans2setfilepathinfo: SMB_SET_FILE_UNIX_LINK doing hard link %s -> %s\n",
				fname, link_dest ));

			if (conn->vfs_ops.link(conn,link_dest,fname) != 0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
			SSVAL(params,0,0);
			send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
			return(-1);
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
	if (S_ISDIR(sbuf.st_mode))
		dosmode |= aDIR;
	else
		dosmode &= ~aDIR;

	DEBUG(6,("dosmode: %x\n"  , dosmode));

	if(!((info_level == SMB_SET_FILE_END_OF_FILE_INFO) ||
			(info_level == SMB_SET_FILE_ALLOCATION_INFO) ||
			(info_level == SMB_FILE_ALLOCATION_INFORMATION) ||
			(info_level == SMB_FILE_END_OF_FILE_INFORMATION))) {
		/*
		 * Only do this test if we are not explicitly
		 * changing the size of a file.
		 */
		if (!size)
			size = get_file_size(sbuf);
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
			 * away and will set it on file close. JRA.
			 */

			if (tvs.modtime != (time_t)0 && tvs.modtime != (time_t)-1) {
				DEBUG(10,("call_trans2setfilepathinfo: setting pending modtime to %s\n",
					ctime(&tvs.modtime) ));
				fsp->pending_modtime = tvs.modtime;
			}

		} else {

			DEBUG(10,("call_trans2setfilepathinfo: setting utimes to modified values.\n"));

			if(file_utime(conn, fname, &tvs)!=0)
				return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	}

	/* check the mode isn't different, before changing it */
	if ((dosmode != 0) && (dosmode != dos_mode(conn, fname, &sbuf))) {

		DEBUG(10,("call_trans2setfilepathinfo: file %s : setting dos mode %x\n",
			fname, dosmode ));

		if(file_chmod(conn, fname, dosmode, NULL)) {
			DEBUG(2,("chmod of %s failed (%s)\n", fname, strerror(errno)));
			return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	}

	if(size != get_file_size(sbuf)) {

		int ret;

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
			ret = vfs_set_filelen(new_fsp, size);
			close_file(new_fsp,True);
		} else {
			ret = vfs_set_filelen(fsp, size);
		}

		if (ret == -1)
			return (UNIXERROR(ERRHRD,ERRdiskfull));
	}

	SSVAL(params,0,0);
	send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
	return(-1);
}

/****************************************************************************
 Reply to a TRANS2_MKDIR (make directory with extended attributes).
****************************************************************************/

static int call_trans2mkdir(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *params = *pparams;
	pstring directory;
	int ret = -1;
	SMB_STRUCT_STAT sbuf;
	BOOL bad_path = False;

	if (!CAN_WRITE(conn))
		return ERROR_DOS(ERRSRV,ERRaccess);

	if (total_params < 4)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	pstrcpy(directory, &params[4]);

	DEBUG(3,("call_trans2mkdir : name = %s\n", directory));

	unix_convert(directory,conn,0,&bad_path,&sbuf);
	if (check_name(directory,conn))
		ret = vfs_mkdir(conn,directory,unix_mode(conn,aDIR,directory));
  
	if(ret < 0) {
		DEBUG(5,("call_trans2mkdir error (%s)\n", strerror(errno)));
		set_bad_path_error(errno, bad_path);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	/* Realloc the parameter and data sizes */
	params = Realloc(*pparams,2);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

	SSVAL(params,0,0);

	send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
  
	return(-1);
}

/****************************************************************************
 Reply to a TRANS2_FINDNOTIFYFIRST (start monitoring a directory for changes).
 We don't actually do this - we just send a null response.
****************************************************************************/

static int call_trans2findnotifyfirst(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	static uint16 fnf_handle = 257;
	char *params = *pparams;
	uint16 info_level;

	if (total_params < 6)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	info_level = SVAL(params,4);
	DEBUG(3,("call_trans2findnotifyfirst - info_level %d\n", info_level));

	switch (info_level) {
		case 1:
		case 2:
			break;
		default:
			return ERROR_DOS(ERRDOS,ERRunknownlevel);
	}

	/* Realloc the parameter and data sizes */
	params = Realloc(*pparams,6);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

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

static int call_trans2findnotifynext(connection_struct *conn, char *inbuf, char *outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *params = *pparams;

	DEBUG(3,("call_trans2findnotifynext\n"));

	/* Realloc the parameter and data sizes */
	params = Realloc(*pparams,4);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);
	*pparams = params;

	SSVAL(params,0,0); /* No changes */
	SSVAL(params,2,0); /* No EA errors */

	send_trans2_replies(outbuf, bufsize, params, 4, *ppdata, 0);
  
	return(-1);
}

/****************************************************************************
 Reply to a TRANS2_GET_DFS_REFERRAL - Shirish Kalele <kalele@veritas.com>.
****************************************************************************/

static int call_trans2getdfsreferral(connection_struct *conn, char* inbuf, char* outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *params = *pparams;
	enum remote_arch_types ra_type = get_remote_arch();
	BOOL NT_arch = ((ra_type == RA_WINNT) || (ra_type == RA_WIN2K));
	pstring pathname;
	int reply_size = 0;
	int max_referral_level;

	DEBUG(10,("call_trans2getdfsreferral\n"));

	if (total_params < 2)
		return(ERROR_DOS(ERRDOS,ERRinvalidparam));

	max_referral_level = SVAL(params,0);

	if(!lp_host_msdfs())
		return ERROR_DOS(ERRDOS,ERRbadfunc);

	/* if pathname is in UNICODE, convert to DOS */
	/* NT always sends in UNICODE, may not set UNICODE flag */
	if(NT_arch || (SVAL(inbuf,smb_flg2) & FLAGS2_UNICODE_STRINGS)) {
		unistr_to_dos(pathname, &params[2], sizeof(pathname));
		DEBUG(10,("UNICODE referral for %s\n",pathname));
	} else
		pstrcpy(pathname,&params[2]);

	if((reply_size = setup_dfs_referral(pathname,max_referral_level,ppdata)) < 0)
		return ERROR_DOS(ERRDOS,ERRbadfile);
    
	SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | FLAGS2_UNICODE_STRINGS | FLAGS2_DFS_PATHNAMES);
	send_trans2_replies(outbuf,bufsize,0,0,*ppdata,reply_size);

	return(-1);
}

#define LMCAT_SPL       0x53
#define LMFUNC_GETJOBID 0x60

/****************************************************************************
  reply to a TRANS2_IOCTL - used for OS/2 printing.
****************************************************************************/

static int call_trans2ioctl(connection_struct *conn, char* inbuf, char* outbuf, int length, int bufsize,
			char **pparams, int total_params, char **ppdata, int total_data)
{
	char *pdata = *ppdata;
	files_struct *fsp = file_fsp(inbuf,smb_vwv15);

	if ((SVAL(inbuf,(smb_setup+4)) == LMCAT_SPL) &&
			(SVAL(inbuf,(smb_setup+6)) == LMFUNC_GETJOBID)) {
		pdata = Realloc(*ppdata, 32);
		if(pdata == NULL)
			return ERROR_DOS(ERRDOS,ERRnomem);
		*ppdata = pdata;

		SSVAL(pdata,0,fsp->print_jobid);                     /* Job number */
		StrnCpy(pdata+2, global_myname, 15);           /* Our NetBIOS name */
		StrnCpy(pdata+18, lp_servicename(SNUM(conn)), 13); /* Service name */
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

int reply_findclose(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
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

int reply_findnclose(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
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

int reply_transs2(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	START_PROFILE(SMBtranss2);
	DEBUG(4,("Ignoring transs2 of length %d\n",length));
	END_PROFILE(SMBtranss2);
	return(-1);
}

/****************************************************************************
 Reply to a SMBtrans2.
****************************************************************************/

int reply_trans2(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
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
	unsigned int num_params, num_params_sofar, num_data, num_data_sofar;
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
			DEBUG(2,("Invalid smb_sucnt in trans2 call(%u)\n",suwcnt));
			DEBUG(2,("Transaction is %d\n",tran_call));
			END_PROFILE(SMBtrans2);
			ERROR_DOS(ERRDOS,ERRinvalidparam);
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

	if(params) {
		unsigned int psoff = SVAL(inbuf, smb_psoff);
		if ((psoff + num_params < psoff) || (psoff + num_params < num_params))
			goto bad_param;
		if (smb_base(inbuf) + psoff + num_params > inbuf + length)
			goto bad_param;
		memcpy( params, smb_base(inbuf) + psoff, num_params);
	}
	if(data) {
		unsigned int dsoff = SVAL(inbuf, smb_dsoff);
		if ((dsoff + num_data < dsoff) || (dsoff + num_data < num_data))
			goto bad_param;
		if (smb_base(inbuf) + dsoff + num_data > inbuf + length)
			goto bad_param;
		memcpy( data, smb_base(inbuf) + dsoff, num_data);
	}

	if(num_data_sofar < total_data || num_params_sofar < total_params)  {
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf,0,0,True);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_trans2: send_smb failed.");

		while (num_data_sofar < total_data || 
		       num_params_sofar < total_params) {
			BOOL ret;
			unsigned int param_disp;
			unsigned int param_off;
			unsigned int data_disp;
			unsigned int data_off;

			ret = receive_next_smb(inbuf,bufsize,SMB_SECONDARY_WAIT);
			
			if ((ret && 
			     (CVAL(inbuf, smb_com) != SMBtranss2)) || !ret) {
				outsize = set_message(outbuf,0,0,True);
				if(ret)
					DEBUG(0,("reply_trans2: Invalid secondary trans2 packet\n"));
				else
					DEBUG(0,("reply_trans2: %s in getting secondary trans2 response.\n",
						 (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
				goto bad_param;
			}
      
			/* Revise total_params and total_data in case
                           they have changed downwards */
			if (SVAL(inbuf, smb_tpscnt) < total_params)
				total_params = SVAL(inbuf, smb_tpscnt);
			if (SVAL(inbuf, smb_tdscnt) < total_data)
				total_data = SVAL(inbuf, smb_tdscnt);

			num_params = SVAL(inbuf,smb_spscnt);
			param_off = SVAL(inbuf, smb_spsoff);
			param_disp = SVAL(inbuf, smb_spsdisp);
			num_params_sofar += num_params;

			num_data = SVAL(inbuf, smb_sdscnt);
			data_off = SVAL(inbuf, smb_sdsoff);
			data_disp = SVAL(inbuf, smb_sdsdisp);
			num_data_sofar += num_data;

			if (num_params_sofar > total_params || num_data_sofar > total_data)
				goto bad_param;
			
			if (num_params) {
				if (param_disp + num_params >= total_params)
					goto bad_param;
				if ((param_disp + num_params < param_disp) ||
						(param_disp + num_params < num_params))
					goto bad_param;
				if (smb_base(inbuf) + param_off + num_params >= inbuf + bufsize)
					goto bad_param;
				if (params + param_disp < params)
					goto bad_param;

				memcpy( &params[param_disp], smb_base(inbuf) + param_off, num_params);
			}
			if (num_data) {
				if (data_disp + num_data >= total_data)
					goto bad_param;
				if ((data_disp + num_data < data_disp) ||
						(data_disp + num_data < num_data))
					goto bad_param;
				if (smb_base(inbuf) + data_off + num_data >= inbuf + bufsize)
					goto bad_param;
				if (data + data_disp < data)
					goto bad_param;

				memcpy( &data[data_disp], smb_base(inbuf) + data_off, num_data);
			}
		}
	}
	
	if (Protocol >= PROTOCOL_NT1)
		SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | FLAGS2_IS_LONG_NAME);

	/* Now we must call the relevant TRANS2 function */
	switch(tran_call)  {
	case TRANSACT2_OPEN:
		START_PROFILE_NESTED(Trans2_open);
		outsize = call_trans2open(conn, inbuf, outbuf, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_open);
		break;

	case TRANSACT2_FINDFIRST:
		START_PROFILE_NESTED(Trans2_findfirst);
		outsize = call_trans2findfirst(conn, inbuf, outbuf, bufsize,
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_findfirst);
		break;

	case TRANSACT2_FINDNEXT:
		START_PROFILE_NESTED(Trans2_findnext);
		outsize = call_trans2findnext(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_findnext);
		break;

	case TRANSACT2_QFSINFO:
		START_PROFILE_NESTED(Trans2_qfsinfo);
	    outsize = call_trans2qfsinfo(conn, inbuf, outbuf, length, bufsize,
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_qfsinfo);
	    break;

	case TRANSACT2_SETFSINFO:
		START_PROFILE_NESTED(Trans2_setfsinfo);
		outsize = call_trans2setfsinfo(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_setfsinfo);
		break;

	case TRANSACT2_QPATHINFO:
	case TRANSACT2_QFILEINFO:
		START_PROFILE_NESTED(Trans2_qpathinfo);
		outsize = call_trans2qfilepathinfo(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_qpathinfo);
		break;
	case TRANSACT2_SETPATHINFO:
	case TRANSACT2_SETFILEINFO:
		START_PROFILE_NESTED(Trans2_setpathinfo);
		outsize = call_trans2setfilepathinfo(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_setpathinfo);
		break;

	case TRANSACT2_FINDNOTIFYFIRST:
		START_PROFILE_NESTED(Trans2_findnotifyfirst);
		outsize = call_trans2findnotifyfirst(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_findnotifyfirst);
		break;

	case TRANSACT2_FINDNOTIFYNEXT:
		START_PROFILE_NESTED(Trans2_findnotifynext);
		outsize = call_trans2findnotifynext(conn, inbuf, outbuf, length, bufsize, 
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_findnotifynext);
		break;
	case TRANSACT2_MKDIR:
		START_PROFILE_NESTED(Trans2_mkdir);
		outsize = call_trans2mkdir(conn, inbuf, outbuf, length, bufsize,
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_mkdir);
		break;

	case TRANSACT2_GET_DFS_REFERRAL:
		START_PROFILE_NESTED(Trans2_get_dfs_referral);
		outsize = call_trans2getdfsreferral(conn,inbuf,outbuf,length, bufsize,
				&params, total_params, &data, total_data);
		END_PROFILE_NESTED(Trans2_get_dfs_referral);
		break;
	case TRANSACT2_IOCTL:
		START_PROFILE_NESTED(Trans2_ioctl);
		outsize = call_trans2ioctl(conn,inbuf,outbuf,length, bufsize,
				&params, total_params, &data, total_data);
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

  bad_param:

	SAFE_FREE(params);
	SAFE_FREE(data);
	END_PROFILE(SMBtrans2);
	return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
}
