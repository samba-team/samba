/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison 1994-1998

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
extern int smb_read_error;
extern int global_oplock_break;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;

static const char *known_nt_pipes[] = {
  "\\LANMAN",
  "\\srvsvc",
  "\\samr",
  "\\wkssvc",
  "\\NETLOGON",
  "\\ntlsa",
  "\\ntsvcs",
  "\\lsass",
  "\\lsarpc",
  "\\winreg",
  "\\spoolss",
#ifdef WITH_MSDFS
  "\\netdfs",
#endif
  NULL
};

/* Map generic permissions to file object specific permissions */
 
struct generic_mapping file_generic_mapping = {
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    FILE_GENERIC_EXECUTE,
    FILE_GENERIC_ALL
};

/****************************************************************************
 Send the required number of replies back.
 We assume all fields other than the data fields are
 set correctly for the type of call.
 HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static int send_nt_replies(char *inbuf, char *outbuf, int bufsize, NTSTATUS nt_error, char *params,
                           int paramsize, char *pdata, int datasize)
{
  extern int max_send;
  int data_to_send = datasize;
  int params_to_send = paramsize;
  int useable_space;
  char *pp = params;
  char *pd = pdata;
  int params_sent_thistime, data_sent_thistime, total_sent_thistime;
  int alignment_offset = 3;
  int data_alignment_offset = 0;

  /*
   * Initially set the wcnt area to be 18 - this is true for all
   * transNT replies.
   */

  set_message(outbuf,18,0,True);

  if(NT_STATUS_V(nt_error)) {
	  ERROR_NT(nt_error);
  }

  /* 
   * If there genuinely are no parameters or data to send just send
   * the empty packet.
   */

  if(params_to_send == 0 && data_to_send == 0) {
    if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("send_nt_replies: send_smb failed.");
    return 0;
  }

  /*
   * When sending params and data ensure that both are nicely aligned.
   * Only do this alignment when there is also data to send - else
   * can cause NT redirector problems.
   */

  if (((params_to_send % 4) != 0) && (data_to_send != 0))
    data_alignment_offset = 4 - (params_to_send % 4);

  /* 
   * Space is bufsize minus Netbios over TCP header minus SMB header.
   * The alignment_offset is to align the param bytes on a four byte
   * boundary (2 bytes for data len, one byte pad). 
   * NT needs this to work correctly.
   */

  useable_space = bufsize - ((smb_buf(outbuf)+
                    alignment_offset+data_alignment_offset) -
                    outbuf);

  /*
   * useable_space can never be more than max_send minus the
   * alignment offset.
   */

  useable_space = MIN(useable_space,
                      max_send - (alignment_offset+data_alignment_offset));


  while (params_to_send || data_to_send) {

    /*
     * Calculate whether we will totally or partially fill this packet.
     */

    total_sent_thistime = params_to_send + data_to_send +
                            alignment_offset + data_alignment_offset;

    /* 
     * We can never send more than useable_space.
     */

    total_sent_thistime = MIN(total_sent_thistime, useable_space);

    set_message(outbuf, 18, total_sent_thistime, True);

    /*
     * Set total params and data to be sent.
     */

    SIVAL(outbuf,smb_ntr_TotalParameterCount,paramsize);
    SIVAL(outbuf,smb_ntr_TotalDataCount,datasize);

    /* 
     * Calculate how many parameters and data we can fit into
     * this packet. Parameters get precedence.
     */

    params_sent_thistime = MIN(params_to_send,useable_space);
    data_sent_thistime = useable_space - params_sent_thistime;
    data_sent_thistime = MIN(data_sent_thistime,data_to_send);

    SIVAL(outbuf,smb_ntr_ParameterCount,params_sent_thistime);

    if(params_sent_thistime == 0) {
      SIVAL(outbuf,smb_ntr_ParameterOffset,0);
      SIVAL(outbuf,smb_ntr_ParameterDisplacement,0);
    } else {
      /*
       * smb_ntr_ParameterOffset is the offset from the start of the SMB header to the
       * parameter bytes, however the first 4 bytes of outbuf are
       * the Netbios over TCP header. Thus use smb_base() to subtract
       * them from the calculation.
       */

      SIVAL(outbuf,smb_ntr_ParameterOffset,
            ((smb_buf(outbuf)+alignment_offset) - smb_base(outbuf)));
      /* 
       * Absolute displacement of param bytes sent in this packet.
       */

      SIVAL(outbuf,smb_ntr_ParameterDisplacement,pp - params);
    }

    /*
     * Deal with the data portion.
     */

    SIVAL(outbuf,smb_ntr_DataCount, data_sent_thistime);

    if(data_sent_thistime == 0) {
      SIVAL(outbuf,smb_ntr_DataOffset,0);
      SIVAL(outbuf,smb_ntr_DataDisplacement, 0);
    } else {
      /*
       * The offset of the data bytes is the offset of the
       * parameter bytes plus the number of parameters being sent this time.
       */

      SIVAL(outbuf,smb_ntr_DataOffset,((smb_buf(outbuf)+alignment_offset) -
            smb_base(outbuf)) + params_sent_thistime + data_alignment_offset);
      SIVAL(outbuf,smb_ntr_DataDisplacement, pd - pdata);
    }

    /* 
     * Copy the param bytes into the packet.
     */

    if(params_sent_thistime)
      memcpy((smb_buf(outbuf)+alignment_offset),pp,params_sent_thistime);

    /*
     * Copy in the data bytes
     */

    if(data_sent_thistime)
      memcpy(smb_buf(outbuf)+alignment_offset+params_sent_thistime+
             data_alignment_offset,pd,data_sent_thistime);
    
    DEBUG(9,("nt_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
          params_sent_thistime, data_sent_thistime, useable_space));
    DEBUG(9,("nt_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
          params_to_send, data_to_send, paramsize, datasize));
    
    /* Send the packet */
    if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("send_nt_replies: send_smb failed.");
    
    pp += params_sent_thistime;
    pd += data_sent_thistime;
    
    params_to_send -= params_sent_thistime;
    data_to_send -= data_sent_thistime;

    /*
     * Sanity check
     */

    if(params_to_send < 0 || data_to_send < 0) {
      DEBUG(0,("send_nt_replies failed sanity check pts = %d, dts = %d\n!!!",
            params_to_send, data_to_send));
      return -1;
    }
  } 

  return 0;
}

/****************************************************************************
 (Hopefully) temporary call to fix bugs in NT5.0beta2. This OS sends unicode
 strings in NT calls AND DOESN'T SET THE UNICODE BIT !!!!!!!
****************************************************************************/

static void get_filename( char *fname, char *inbuf, int data_offset, int data_len, int fname_len)
{
	/*
	 * We need various heuristics here to detect a unicode string... JRA.
	 */

	DEBUG(10,("get_filename: data_offset = %d, data_len = %d, fname_len = %d\n",
			data_offset, data_len, fname_len ));

	if(data_len - fname_len > 1) {
		/*
		 * NT 5.0 Beta 2 has kindly sent us a UNICODE string
		 * without bothering to set the unicode bit. How kind.
		 *
		 * Firstly - ensure that the data offset is aligned
		 * on a 2 byte boundary - add one if not.
		 */
		fname_len = fname_len/2;
		if(data_offset & 1)
			data_offset++;
		pstrcpy(fname, dos_unistrn2((uint16 *)(inbuf+data_offset), fname_len));
	} else {
		StrnCpy(fname,inbuf+data_offset,fname_len);
		fname[fname_len] = '\0';
	}
}

/****************************************************************************
 Fix bugs in Win2000 final release. In trans calls this OS sends unicode
 strings AND DOESN'T SET THE UNICODE BIT !!!!!!!
****************************************************************************/

static void get_filename_transact( char *fname, char *inbuf, int data_offset, int data_len, int fname_len)
{
	DEBUG(10,("get_filename_transact: data_offset = %d, data_len = %d, fname_len = %d\n",
			data_offset, data_len, fname_len ));

	/*
	 * Win2K sends a unicode filename plus one extra alingment byte.
	 * WinNT4.x send an ascii string with multiple garbage bytes on
	 * the end here.
	 */

	/*
	 * We need various heuristics here to detect a unicode string... JRA.
	 */

	if( ((fname_len % 2) == 0) &&
		(
			(data_len == 1) ||
			(inbuf[data_offset] == '\0') ||
			((fname_len > 1) && (inbuf[data_offset+1] == '\\') && (inbuf[data_offset+2] == '\0'))
		)) {

		/*
		 * Ensure that the data offset is aligned
		 * on a 2 byte boundary - add one if not.
		 */
		fname_len = fname_len/2;
		if(data_offset & 1)
			data_offset++;
		pstrcpy(fname, dos_unistrn2((uint16 *)(inbuf+data_offset), fname_len));
	} else {
		StrnCpy(fname,inbuf+data_offset,fname_len);
		fname[fname_len] = '\0';
	}
}

/****************************************************************************
 Save case statics.
****************************************************************************/

static BOOL saved_case_sensitive;
static BOOL saved_case_preserve;
static BOOL saved_short_case_preserve;

/****************************************************************************
 Save case semantics.
****************************************************************************/

static void set_posix_case_semantics(uint32 file_attributes)
{
	if(!(file_attributes & FILE_FLAG_POSIX_SEMANTICS))
		return;

	saved_case_sensitive = case_sensitive;
	saved_case_preserve = case_preserve;
	saved_short_case_preserve = short_case_preserve;

	/* Set to POSIX. */
	case_sensitive = True;
	case_preserve = True;
	short_case_preserve = True;
}

/****************************************************************************
 Restore case semantics.
****************************************************************************/

static void restore_case_semantics(uint32 file_attributes)
{
	if(!(file_attributes & FILE_FLAG_POSIX_SEMANTICS))
		return;

	case_sensitive = saved_case_sensitive;
	case_preserve = saved_case_preserve;
	short_case_preserve = saved_short_case_preserve;
}

/****************************************************************************
 Utility function to map create disposition.
****************************************************************************/

static int map_create_disposition( uint32 create_disposition)
{
	int ret;

	switch( create_disposition ) {
		case FILE_CREATE:
			/* create if not exist, fail if exist */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_FAIL);
			break;
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
			/* create if not exist, trunc if exist */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE);
			break;
		case FILE_OPEN:
			/* fail if not exist, open if exists */
			ret = (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN);
			break;
		case FILE_OPEN_IF:
			/* create if not exist, open if exists */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_OPEN);
			break;
		case FILE_OVERWRITE:
			/* fail if not exist, truncate if exists */
			ret = (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE);
			break;
		default:
			DEBUG(0,("map_create_disposition: Incorrect value for create_disposition = %d\n",
				create_disposition ));
			return -1;
	}

	DEBUG(10,("map_create_disposition: Mapped create_disposition 0x%lx to 0x%x\n",
		(unsigned long)create_disposition, ret ));

	return ret;
}

/****************************************************************************
 Utility function to map share modes.
****************************************************************************/

static int map_share_mode( char *fname, uint32 create_options,
			uint32 *desired_access, uint32 share_access, uint32 file_attributes)
{
	int smb_open_mode = -1;

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(desired_access, &file_generic_mapping);

	switch( *desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA) ) {
		case FILE_READ_DATA:
			smb_open_mode = DOS_OPEN_RDONLY;
			break;
		case FILE_WRITE_DATA:
		case FILE_APPEND_DATA:
		case FILE_WRITE_DATA|FILE_APPEND_DATA:
			smb_open_mode = DOS_OPEN_WRONLY;
			break;
		case FILE_READ_DATA|FILE_WRITE_DATA:
		case FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA:
		case FILE_READ_DATA|FILE_APPEND_DATA:
			smb_open_mode = DOS_OPEN_RDWR;
			break;
	}

	/*
	 * NB. For DELETE_ACCESS we should really check the
	 * directory permissions, as that is what controls
	 * delete, and for WRITE_DAC_ACCESS we should really
	 * check the ownership, as that is what controls the
	 * chmod. Note that this is *NOT* a security hole (this
	 * note is for you, Andrew) as we are not *allowing*
	 * the access at this point, the actual unlink or
	 * chown or chmod call would do this. We are just helping
	 * clients out by telling them if they have a hope
	 * of any of this succeeding. POSIX acls may still
	 * deny the real call. JRA.
	 */

	if (smb_open_mode == -1) {

		if(*desired_access & (DELETE_ACCESS|WRITE_DAC_ACCESS|WRITE_OWNER_ACCESS|SYNCHRONIZE_ACCESS|
				FILE_EXECUTE|FILE_READ_ATTRIBUTES|
				FILE_READ_EA|FILE_WRITE_EA|SYSTEM_SECURITY_ACCESS|
				FILE_WRITE_ATTRIBUTES|READ_CONTROL_ACCESS)) {
			smb_open_mode = DOS_OPEN_RDONLY;
		} else if(*desired_access == 0) {

			/* 
			 * JRA - NT seems to sometimes send desired_access as zero. play it safe
			 * and map to a stat open.
			 */

			smb_open_mode = DOS_OPEN_RDONLY;

		} else {
			DEBUG(0,("map_share_mode: Incorrect value 0x%lx for desired_access to file %s\n",
				(unsigned long)*desired_access, fname));
			return -1;
		}
	}

	/*
	 * Set the special bit that means allow share delete.
	 * This is held outside the normal share mode bits at 1<<15.
	 * JRA.
	 */

	if(share_access & FILE_SHARE_DELETE) {
		smb_open_mode |= ALLOW_SHARE_DELETE;
		DEBUG(10,("map_share_mode: FILE_SHARE_DELETE requested. open_mode = 0x%x\n", smb_open_mode));
	}

	/*
	 * We need to store the intent to open for Delete. This
	 * is what determines if a delete on close flag can be set.
	 * This is the wrong way (and place) to store this, but for 2.2 this
	 * is the only practical way. JRA.
	 */

	if(*desired_access & DELETE_ACCESS) {
		DEBUG(10,("map_share_mode: DELETE_ACCESS requested. open_mode = 0x%x\n", smb_open_mode));
	}

	if (create_options & FILE_DELETE_ON_CLOSE) {
		/* Implicit delete access is *NOT* requested... */
		smb_open_mode |= DELETE_ON_CLOSE_FLAG;
		DEBUG(10,("map_share_mode: FILE_DELETE_ON_CLOSE requested. open_mode = 0x%x\n", smb_open_mode));
	}

	/* Add in the requested share mode. */
	switch( share_access & (FILE_SHARE_READ|FILE_SHARE_WRITE)) {
		case FILE_SHARE_READ:
			smb_open_mode |= SET_DENY_MODE(DENY_WRITE);
			break;
		case FILE_SHARE_WRITE:
			smb_open_mode |= SET_DENY_MODE(DENY_READ);
			break;
		case (FILE_SHARE_READ|FILE_SHARE_WRITE):
			smb_open_mode |= SET_DENY_MODE(DENY_NONE);
			break;
		case FILE_SHARE_NONE:
			smb_open_mode |= SET_DENY_MODE(DENY_ALL);
			break;
	}

	/*
	 * Handle an O_SYNC request.
	 */

	if(file_attributes & FILE_FLAG_WRITE_THROUGH)
		smb_open_mode |= FILE_SYNC_OPENMODE;

	DEBUG(10,("map_share_mode: Mapped desired access 0x%lx, share access 0x%lx, file attributes 0x%lx \
to open_mode 0x%x\n", (unsigned long)*desired_access, (unsigned long)share_access,
		(unsigned long)file_attributes, smb_open_mode ));
 
	return smb_open_mode;
}

/****************************************************************************
 Reply to an NT create and X call on a pipe.
****************************************************************************/

static int nt_open_pipe(char *fname, connection_struct *conn,
			char *inbuf, char *outbuf, int *ppnum)
{
	pipes_struct *p = NULL;

	uint16 vuid = SVAL(inbuf, smb_uid);
	int i;

	DEBUG(4,("nt_open_pipe: Opening pipe %s.\n", fname));
    
	/* See if it is one we want to handle. */

	if (lp_disable_spoolss() && strequal(fname, "\\spoolss"))
		return(ERROR_BOTH(NT_STATUS_OBJECT_NAME_NOT_FOUND,ERRDOS,ERRbadpipe));

	for( i = 0; known_nt_pipes[i]; i++ )
		if( strequal(fname,known_nt_pipes[i]))
			break;
    
	if ( known_nt_pipes[i] == NULL )
		return(ERROR_BOTH(NT_STATUS_OBJECT_NAME_NOT_FOUND,ERRDOS,ERRbadpipe));
    
	/* Strip \\ off the name. */
	fname++;
    
	DEBUG(3,("nt_open_pipe: Known pipe %s opening.\n", fname));

	p = open_rpc_pipe_p(fname, conn, vuid);
	if (!p)
		return(ERROR_DOS(ERRSRV,ERRnofids));

	*ppnum = p->pnum;

	return 0;
}

/****************************************************************************
 Reply to an NT create and X call for pipes.
****************************************************************************/

static int do_ntcreate_pipe_open(connection_struct *conn,
			 char *inbuf,char *outbuf,int length,int bufsize)
{
	pstring fname;
	int ret;
	int pnum = -1;
	char *p = NULL;
	uint32 fname_len = MIN(((uint32)SVAL(inbuf,smb_ntcreate_NameLength)),
			       ((uint32)sizeof(fname)-1));

	get_filename(fname, inbuf, smb_buf(inbuf)-inbuf, 
                  smb_buflen(inbuf),fname_len);
	if ((ret = nt_open_pipe(fname, conn, inbuf, outbuf, &pnum)) != 0)
		return ret;

	/*
	 * Deal with pipe return.
	 */  

	set_message(outbuf,34,0,True);

	p = outbuf + smb_vwv2;
	p++;
	SSVAL(p,0,pnum);
	p += 2;
	SIVAL(p,0,FILE_WAS_OPENED);
	p += 4;
	p += 32;
	SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
	p += 20;
	/* File type. */
	SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
	/* Device state. */
	SSVAL(p,2, 0x5FF); /* ? */

	DEBUG(5,("do_ntcreate_pipe_open: open pipe = %s\n", fname));

	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to an NT create and X call.
****************************************************************************/

int reply_ntcreate_and_X(connection_struct *conn,
			 char *inbuf,char *outbuf,int length,int bufsize)
{  
	int result;
	pstring fname;
	uint32 flags = IVAL(inbuf,smb_ntcreate_Flags);
	uint32 desired_access = IVAL(inbuf,smb_ntcreate_DesiredAccess);
	uint32 file_attributes = IVAL(inbuf,smb_ntcreate_FileAttributes);
	uint32 share_access = IVAL(inbuf,smb_ntcreate_ShareAccess);
	uint32 create_disposition = IVAL(inbuf,smb_ntcreate_CreateDisposition);
	uint32 create_options = IVAL(inbuf,smb_ntcreate_CreateOptions);
	uint32 fname_len = MIN(((uint32)SVAL(inbuf,smb_ntcreate_NameLength)),
			       ((uint32)sizeof(fname)-1));
	uint16 root_dir_fid = (uint16)IVAL(inbuf,smb_ntcreate_RootDirectoryFid);
	SMB_BIG_UINT allocation_size = 0;
	int smb_ofun;
	int smb_open_mode;
	int smb_attr = (file_attributes & SAMBA_ATTRIBUTES_MASK);
	/* Breakout the oplock request bits so we can set the
	   reply bits separately. */
	int oplock_request = 0;
	mode_t unixmode;
	int fmode=0,rmode=0;
	SMB_OFF_T file_len = 0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	BOOL bad_path = False;
	files_struct *fsp=NULL;
	char *p = NULL;
	time_t c_time;
	BOOL extended_oplock_granted = False;

	START_PROFILE(SMBntcreateX);

	DEBUG(10,("reply_ntcreateX: flags = 0x%x, desired_access = 0x%x \
file_attributes = 0x%x, share_access = 0x%x, create_disposition = 0x%x \
create_options = 0x%x root_dir_fid = 0x%x\n", flags, desired_access, file_attributes,
			share_access, create_disposition,
			root_dir_fid, create_options ));

	/* If it's an IPC, use the pipe handler. */

	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			END_PROFILE(SMBntcreateX);
			return do_ntcreate_pipe_open(conn,inbuf,outbuf,length,bufsize);
		} else {
			END_PROFILE(SMBntcreateX);
			return(ERROR_DOS(ERRDOS,ERRnoaccess));
		}
	}
			
	if (create_options & FILE_OPEN_BY_FILE_ID) {
		END_PROFILE(SMBntcreateX);
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}

	/* 
	 * We need to construct the open_and_X ofun value from the
	 * NT values, as that's what our code is structured to accept.
	 */    
	
	if((smb_ofun = map_create_disposition( create_disposition )) == -1) {
		END_PROFILE(SMBntcreateX);
		return(ERROR_DOS(ERRDOS,ERRnoaccess));
	}

	/*
	 * Get the file name.
	 */

	if(root_dir_fid != 0) {
		/*
		 * This filename is relative to a directory fid.
		 */
		files_struct *dir_fsp = file_fsp(inbuf,smb_ntcreate_RootDirectoryFid);
		size_t dir_name_len;

		if(!dir_fsp) {
			END_PROFILE(SMBntcreateX);
			return(ERROR_DOS(ERRDOS,ERRbadfid));
		}

		if(!dir_fsp->is_directory) {

			get_filename(&fname[0], inbuf, smb_buf(inbuf)-inbuf, 
				smb_buflen(inbuf),fname_len);

			/* 
			 * Check to see if this is a mac fork of some kind.
			 */

			if( strchr(fname, ':')) {
				END_PROFILE(SMBntcreateX);
				return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
			}
			END_PROFILE(SMBntcreateX);
			return(ERROR_DOS(ERRDOS,ERRbadfid));
		}

		/*
		 * Copy in the base directory name.
		 */

		pstrcpy( fname, dir_fsp->fsp_name );
		dir_name_len = strlen(fname);

		/*
		 * Ensure it ends in a '\'.
		 */

		if(fname[dir_name_len-1] != '\\' && fname[dir_name_len-1] != '/') {
			pstrcat(fname, "\\");
			dir_name_len++;
		}

		/*
		 * This next calculation can refuse a correct filename if we're dealing
		 * with the Win2k unicode bug, but that would be rare. JRA.
		 */

		if(fname_len + dir_name_len >= sizeof(pstring)) {
			END_PROFILE(SMBntcreateX);
			return(ERROR_DOS(ERRSRV,ERRfilespecs));
		}

		get_filename(&fname[dir_name_len], inbuf, smb_buf(inbuf)-inbuf, 
			smb_buflen(inbuf),fname_len);

	} else {
      
		get_filename(fname, inbuf, smb_buf(inbuf)-inbuf, 
			smb_buflen(inbuf),fname_len);

		/* 
		 * Check to see if this is a mac fork of some kind.
		 */

		if( strchr(fname, ':')) {
			END_PROFILE(SMBntcreateX);
			return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
		}
	}
	
	/*
	 * Now contruct the smb_open_mode value from the filename, 
	 * desired access and the share access.
	 */
	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	if((smb_open_mode = map_share_mode(fname, create_options, &desired_access, 
					   share_access, 
					   file_attributes)) == -1) {
		END_PROFILE(SMBntcreateX);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	if (oplock_request) {
		oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;
	}

	/*
	 * Ordinary file or directory.
	 */
		
	/*
	 * Check if POSIX semantics are wanted.
	 */
		
	set_posix_case_semantics(file_attributes);
		
	unix_convert(fname,conn,0,&bad_path,&sbuf);
		
	unixmode = unix_mode(conn,smb_attr | aARCH, fname);
    
	/* 
	 * If it's a request for a directory open, deal with it separately.
	 */

	if(create_options & FILE_DIRECTORY_FILE) {
		oplock_request = 0;
		
		/* Can't open a temp directory. IFS kit test. */
		if (file_attributes & FILE_ATTRIBUTE_TEMPORARY) {
			END_PROFILE(SMBntcreateX);
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		fsp = open_directory(conn, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, unixmode, &smb_action);
			
		restore_case_semantics(file_attributes);

		if(!fsp) {
			set_bad_path_error(errno, bad_path);
			END_PROFILE(SMBntcreateX);
			return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	} else {
		/*
		 * Ordinary file case.
		 */

		/* NB. We have a potential bug here. If we
		 * cause an oplock break to ourselves, then we
		 * could end up processing filename related
		 * SMB requests whilst we await the oplock
		 * break response. As we may have changed the
		 * filename case semantics to be POSIX-like,
		 * this could mean a filename request could
		 * fail when it should succeed. This is a rare
		 * condition, but eventually we must arrange
		 * to restore the correct case semantics
		 * before issuing an oplock break request to
		 * our client. JRA.  */

		fsp = open_file_shared1(conn,fname,&sbuf,
					desired_access,
					smb_open_mode,
					smb_ofun, unixmode, oplock_request,
					&rmode,&smb_action);

		if (!fsp) { 
			/* We cheat here. There are two cases we
			 * care about. One is a directory rename,
			 * where the NT client will attempt to
			 * open the source directory for
			 * DELETE access. Note that when the
			 * NT client does this it does *not*
			 * set the directory bit in the
			 * request packet. This is translated
			 * into a read/write open
			 * request. POSIX states that any open
			 * for write request on a directory
			 * will generate an EISDIR error, so
			 * we can catch this here and open a
			 * pseudo handle that is flagged as a
			 * directory. The second is an open
			 * for a permissions read only, which
			 * we handle in the open_file_stat case. JRA.
			 */

			if(errno == EISDIR) {

				/*
				 * Fail the open if it was explicitly a non-directory file.
				 */

				if (create_options & FILE_NON_DIRECTORY_FILE) {
					restore_case_semantics(file_attributes);
					SSVAL(outbuf, smb_flg2, 
					      SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
					END_PROFILE(SMBntcreateX);
					return ERROR_NT(NT_STATUS_FILE_IS_A_DIRECTORY);
				}
	
				oplock_request = 0;
				fsp = open_directory(conn, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, unixmode, &smb_action);
				
				if(!fsp) {
					restore_case_semantics(file_attributes);
					set_bad_path_error(errno, bad_path);
					END_PROFILE(SMBntcreateX);
					return(UNIXERROR(ERRDOS,ERRnoaccess));
				}
			} else {

				restore_case_semantics(file_attributes);
				set_bad_path_error(errno, bad_path);
				
				END_PROFILE(SMBntcreateX);
				return(UNIXERROR(ERRDOS,ERRnoaccess));
			}
		} 
	}
		
	restore_case_semantics(file_attributes);
		
	file_len = sbuf.st_size;
	fmode = dos_mode(conn,fname,&sbuf);
	if(fmode == 0)
		fmode = FILE_ATTRIBUTE_NORMAL;
	if (!fsp->is_directory && (fmode & aDIR)) {
		close_file(fsp,False);
		END_PROFILE(SMBntcreateX);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	} 
	
	/* Save the requested allocation size. */
	allocation_size = (SMB_BIG_UINT)IVAL(inbuf,smb_ntcreate_AllocationSize);
#ifdef LARGE_SMB_OFF_T
	allocation_size |= (((SMB_BIG_UINT)IVAL(inbuf,smb_ntcreate_AllocationSize + 4)) << 32);
#endif
	if (allocation_size && (allocation_size > (SMB_BIG_UINT)file_len)) {
		fsp->initial_allocation_size = SMB_ROUNDUP(allocation_size,SMB_ROUNDUP_ALLOCATION_SIZE);
		if (vfs_allocate_file_space(fsp, fsp->initial_allocation_size) == -1) {
			close_file(fsp,False);
			END_PROFILE(SMBntcreateX);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
	} else {
		fsp->initial_allocation_size = SMB_ROUNDUP(((SMB_BIG_UINT)file_len),SMB_ROUNDUP_ALLOCATION_SIZE);
	}

	/* 
	 * If the caller set the extended oplock request bit
	 * and we granted one (by whatever means) - set the
	 * correct bit for extended oplock reply.
	 */
	
	if (oplock_request && lp_fake_oplocks(SNUM(conn)))
		extended_oplock_granted = True;
	
	if(oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		extended_oplock_granted = True;

#if 0 
	/* W2K sends back 42 words here ! If we do the same it breaks offline sync. Go figure... ? JRA. */
	set_message(outbuf,42,0,True);
#else
	set_message(outbuf,34,0,True);
#endif
	
	p = outbuf + smb_vwv2;
	
	/*
	 * Currently as we don't support level II oplocks we just report
	 * exclusive & batch here.
	 */

	if (extended_oplock_granted) {
		if (flags & REQUEST_BATCH_OPLOCK) {
			SCVAL(p,0, BATCH_OPLOCK_RETURN);
		} else {
			SCVAL(p,0, EXCLUSIVE_OPLOCK_RETURN);
		}
	} else if (LEVEL_II_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(p,0, LEVEL_II_OPLOCK_RETURN);
	} else {
		SCVAL(p,0,NO_OPLOCK_RETURN);
	}
	
	p++;
	SSVAL(p,0,fsp->fnum);
	p += 2;
	if ((create_disposition == FILE_SUPERSEDE) && (smb_action == FILE_WAS_OVERWRITTEN))
		SIVAL(p,0,FILE_WAS_SUPERSEDED);
	else
		SIVAL(p,0,smb_action);
	p += 4;
	
	/* Create time. */  
	c_time = get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn)));

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		c_time &= ~1;
		sbuf.st_atime &= ~1;
		sbuf.st_mtime &= ~1;
		sbuf.st_mtime &= ~1;
	}

	put_long_date(p,c_time);
	p += 8;
	put_long_date(p,sbuf.st_atime); /* access time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* write time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* change time */
	p += 8;
	SIVAL(p,0,fmode); /* File Attributes. */
	p += 4;
	SOFF_T(p, 0, get_allocation_size(fsp, &sbuf));
	p += 8;
	SOFF_T(p,0,file_len);
	p += 12;
	SCVAL(p,0,fsp->is_directory ? 1 : 0);
	
	DEBUG(5,("reply_ntcreate_and_X: fnum = %d, open name = %s\n", fsp->fnum, fsp->fsp_name));

	result = chain_reply(inbuf,outbuf,length,bufsize);
	END_PROFILE(SMBntcreateX);
	return result;
}

/****************************************************************************
 Reply to a NT_TRANSACT_CREATE call to open a pipe.
****************************************************************************/

static int do_nt_transact_create_pipe( connection_struct *conn,
					char *inbuf, char *outbuf, int length, 
					int bufsize, char **ppsetup, char **ppparams, 
					char **ppdata)
{
	pstring fname;
	uint32 fname_len;
	int total_parameter_count = (int)IVAL(inbuf, smb_nt_TotalParameterCount);
	char *params = *ppparams;
	int ret;
	int pnum = -1;
	char *p = NULL;

	/*
	 * Ensure minimum number of parameters sent.
	 */

	if(total_parameter_count < 54) {
		DEBUG(0,("do_nt_transact_create_pipe - insufficient parameters (%u)\n", (unsigned int)total_parameter_count));
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	fname_len = MIN(((uint32)IVAL(params,44)),((uint32)sizeof(fname)-1));

	get_filename_transact(&fname[0], params, 53,
			total_parameter_count - 53 - fname_len, fname_len);

	if ((ret = nt_open_pipe(fname, conn, inbuf, outbuf, &pnum)) != 0)
		return ret;

	/* Realloc the size of parameters and data we will return */
	params = Realloc(*ppparams, 69);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);

	*ppparams = params;

	memset((char *)params,'\0',69);

	p = params;
	SCVAL(p,0,NO_OPLOCK_RETURN);

	p += 2;
	SSVAL(p,0,pnum);
	p += 2;
	SIVAL(p,0,FILE_WAS_OPENED);
	p += 8;

	p += 32;
	SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
	p += 20;
	/* File type. */
	SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
	/* Device state. */
	SSVAL(p,2, 0x5FF); /* ? */

	DEBUG(5,("do_nt_transact_create_pipe: open name = %s\n", fname));

	/* Send the required number of replies */
	send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, params, 69, *ppdata, 0);

	return -1;
}

/****************************************************************************
 Internal fn to set security descriptors.
****************************************************************************/

static BOOL set_sd(files_struct *fsp, char *data, uint32 sd_len, uint32 security_info_sent, int *pdef_class,uint32 *pdef_code)
{
	prs_struct pd;
	SEC_DESC *psd = NULL;
	TALLOC_CTX *mem_ctx;
	BOOL ret;

	if (sd_len == 0) {
		*pdef_class = 0;
		*pdef_code = 0;
		return True;
	}

	/*
	 * Init the parse struct we will unmarshall from.
	 */

	if ((mem_ctx = talloc_init()) == NULL) {
		DEBUG(0,("set_sd: talloc_init failed.\n"));
		*pdef_class = ERRDOS;
		*pdef_code = ERRnomem;
		return False;
	}

	prs_init(&pd, 0, mem_ctx, UNMARSHALL);

	/*
	 * Setup the prs_struct to point at the memory we just
	 * allocated.
	 */
	
	prs_give_memory( &pd, data, sd_len, False);

	/*
	 * Finally, unmarshall from the data buffer.
	 */

	if(!sec_io_desc( "sd data", &psd, &pd, 1)) {
		DEBUG(0,("set_sd: Error in unmarshalling security descriptor.\n"));
		/*
		 * Return access denied for want of a better error message..
		 */ 
		talloc_destroy(mem_ctx);
		*pdef_class = ERRDOS;
		*pdef_code = ERRnomem;
		return False;
	}

	if (psd->off_owner_sid==0)
		security_info_sent &= ~OWNER_SECURITY_INFORMATION;
	if (psd->off_grp_sid==0)
		security_info_sent &= ~GROUP_SECURITY_INFORMATION;
	if (psd->off_sacl==0)
		security_info_sent &= ~SACL_SECURITY_INFORMATION;
	if (psd->off_dacl==0)
		security_info_sent &= ~DACL_SECURITY_INFORMATION;
	
	ret = fsp->conn->vfs_ops.fset_nt_acl( fsp, fsp->fd, security_info_sent, psd);

	if (!ret) {
		talloc_destroy(mem_ctx);
		*pdef_class = ERRDOS;
		*pdef_code = ERRnoaccess;
		return False;
	}

	talloc_destroy(mem_ctx);

	*pdef_class = 0;
	*pdef_code = 0;
	return True;
}

/****************************************************************************
 Reply to a NT_TRANSACT_CREATE call (needs to process SD's).
****************************************************************************/

static int call_nt_transact_create(connection_struct *conn,
					char *inbuf, char *outbuf, int length, 
					int bufsize, char **ppsetup, char **ppparams, 
					char **ppdata)
{
	pstring fname;
	char *params = *ppparams;
	char *data = *ppdata;
	int total_parameter_count = (int)IVAL(inbuf, smb_nt_TotalParameterCount);
	/* Breakout the oplock request bits so we can set the reply bits separately. */
	int oplock_request = 0;
	mode_t unixmode;
	int fmode=0,rmode=0;
	SMB_OFF_T file_len = 0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	BOOL bad_path = False;
	files_struct *fsp = NULL;
	char *p = NULL;
	BOOL extended_oplock_granted = False;
	uint32 flags;
	uint32 desired_access;
	uint32 file_attributes;
	uint32 share_access;
	uint32 create_disposition;
	uint32 create_options;
	uint32 fname_len;
	uint32 sd_len;
	uint16 root_dir_fid;
	SMB_BIG_UINT allocation_size;
	int smb_ofun;
	int smb_open_mode;
	int smb_attr;
	int error_class;
	uint32 error_code;
	time_t c_time;

	DEBUG(5,("call_nt_transact_create\n"));

	/*
	 * If it's an IPC, use the pipe handler.
	 */

	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support())
			return do_nt_transact_create_pipe(conn, inbuf, outbuf, length, 
					bufsize, ppsetup, ppparams, ppdata);
		else
			return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	/*
	 * Ensure minimum number of parameters sent.
	 */

	if(total_parameter_count < 54) {
		DEBUG(0,("call_nt_transact_create - insufficient parameters (%u)\n", (unsigned int)total_parameter_count));
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	flags = IVAL(params,0);
	desired_access = IVAL(params,8);
	file_attributes = IVAL(params,20);
	share_access = IVAL(params,24);
	create_disposition = IVAL(params,28);
	create_options = IVAL(params,32);
	sd_len = IVAL(params,36);
	fname_len = MIN(((uint32)IVAL(params,44)),((uint32)sizeof(fname)-1));
	root_dir_fid = (uint16)IVAL(params,4);
	smb_attr = (file_attributes & SAMBA_ATTRIBUTES_MASK);

	if (create_options & FILE_OPEN_BY_FILE_ID) {
		END_PROFILE(SMBntcreateX);
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}

	/* 
	 * We need to construct the open_and_X ofun value from the
	 * NT values, as that's what our code is structured to accept.
	 */    

	if((smb_ofun = map_create_disposition( create_disposition )) == -1)
		return ERROR_DOS(ERRDOS,ERRbadmem);

	/*
	 * Get the file name.
	 */

	if(root_dir_fid != 0) {
		/*
		 * This filename is relative to a directory fid.
		 */

		files_struct *dir_fsp = file_fsp(params,4);
		size_t dir_name_len;

		if(!dir_fsp)
			return ERROR_DOS(ERRDOS,ERRbadfid);

		if(!dir_fsp->is_directory) {
			get_filename_transact(&fname[0], params, 53,
					total_parameter_count - 53 - fname_len, fname_len);

			/*
			 * Check to see if this is a mac fork of some kind.
			 */

			if( strchr(fname, ':'))
				return(ERROR_BOTH(NT_STATUS_OBJECT_PATH_NOT_FOUND,ERRDOS,ERRbadpath));

			return(ERROR_DOS(ERRDOS,ERRbadfid));
		}

		/*
		 * Copy in the base directory name.
		 */

		pstrcpy( fname, dir_fsp->fsp_name );
		dir_name_len = strlen(fname);

		/*
		 * Ensure it ends in a '\'.
		 */

		if((fname[dir_name_len-1] != '\\') && (fname[dir_name_len-1] != '/')) {
			pstrcat(fname, "\\");
			dir_name_len++;
		}

		/*
		 * This next calculation can refuse a correct filename if we're dealing
		 * with the Win2k unicode bug, but that would be rare. JRA.
		 */

		if(fname_len + dir_name_len >= sizeof(pstring))
			return(ERROR_DOS(ERRSRV,ERRfilespecs));

		get_filename_transact(&fname[dir_name_len], params, 53,
				total_parameter_count - 53 - fname_len, fname_len);

	} else {
		get_filename_transact(&fname[0], params, 53,
				total_parameter_count - 53 - fname_len, fname_len);

		/*
		 * Check to see if this is a mac fork of some kind.
		 */

		if( strchr(fname, ':'))
			return(ERROR_BOTH(NT_STATUS_OBJECT_PATH_NOT_FOUND,ERRDOS,ERRbadpath));
	}

	/*
	 * Now contruct the smb_open_mode value from the desired access
	 * and the share access.
	 */

	if((smb_open_mode = map_share_mode( fname, create_options, &desired_access,
					share_access, file_attributes)) == -1)
		return ERROR_DOS(ERRDOS,ERRnoaccess);

	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;

	/*
	 * Check if POSIX semantics are wanted.
	 */

	set_posix_case_semantics(file_attributes);
    
	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);
    
	unixmode = unix_mode(conn,smb_attr | aARCH, fname);
   
	/*
	 * If it's a request for a directory open, deal with it separately.
	 */

	if(create_options & FILE_DIRECTORY_FILE) {

		/* Can't open a temp directory. IFS kit test. */
		if (file_attributes & FILE_ATTRIBUTE_TEMPORARY) {
			END_PROFILE(SMBntcreateX);
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		oplock_request = 0;

		/*
		 * We will get a create directory here if the Win32
		 * app specified a security descriptor in the 
		 * CreateDirectory() call.
		 */

		fsp = open_directory(conn, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, unixmode, &smb_action);

		if(!fsp) {
			restore_case_semantics(file_attributes);
			set_bad_path_error(errno, bad_path);
			return(UNIXERROR(ERRDOS,ERRnoaccess));
		}

	} else {

		/*
		 * Ordinary file case.
		 */

		fsp = open_file_shared1(conn,fname,&sbuf,desired_access,smb_open_mode,smb_ofun,unixmode,
				oplock_request,&rmode,&smb_action);

		if (!fsp) { 

			if(errno == EISDIR) {

				/*
				 * Fail the open if it was explicitly a non-directory file.
				 */

				if (create_options & FILE_NON_DIRECTORY_FILE) {
					restore_case_semantics(file_attributes);
					SSVAL(outbuf, smb_flg2, SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
					return ERROR_NT(NT_STATUS_FILE_IS_A_DIRECTORY);
				}
	
				oplock_request = 0;
				fsp = open_directory(conn, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, unixmode, &smb_action);

				if(!fsp) {
					restore_case_semantics(file_attributes);
					set_bad_path_error(errno, bad_path);
					return(UNIXERROR(ERRDOS,ERRnoaccess));
				}
			} else {

				restore_case_semantics(file_attributes);
				set_bad_path_error(errno, bad_path);

				return(UNIXERROR(ERRDOS,ERRnoaccess));
			}
		} 
  
		file_len = sbuf.st_size;
		fmode = dos_mode(conn,fname,&sbuf);
		if(fmode == 0)
			fmode = FILE_ATTRIBUTE_NORMAL;

		if (fmode & aDIR) {
			close_file(fsp,False);
			restore_case_semantics(file_attributes);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		} 

		/* 
		 * If the caller set the extended oplock request bit
		 * and we granted one (by whatever means) - set the
		 * correct bit for extended oplock reply.
		 */
    
		if (oplock_request && lp_fake_oplocks(SNUM(conn)))
			extended_oplock_granted = True;
  
		if(oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
			extended_oplock_granted = True;
	}

	/*
	 * Now try and apply the desired SD.
	 */

	if (sd_len && !set_sd( fsp, data, sd_len, ALL_SECURITY_INFORMATION, &error_class, &error_code)) {
		close_file(fsp,False);
		restore_case_semantics(file_attributes);
		return ERROR_DOS(error_class, error_code);
	}

	restore_case_semantics(file_attributes);

	/* Save the requested allocation size. */
	allocation_size = (SMB_BIG_UINT)IVAL(params,12);
#ifdef LARGE_SMB_OFF_T
	allocation_size |= (((SMB_BIG_UINT)IVAL(params,16)) << 32);
#endif
	if (allocation_size && (allocation_size > file_len)) {
		fsp->initial_allocation_size = SMB_ROUNDUP(allocation_size,SMB_ROUNDUP_ALLOCATION_SIZE);
		if (vfs_allocate_file_space(fsp, fsp->initial_allocation_size) == -1) {
			close_file(fsp,False);
			END_PROFILE(SMBntcreateX);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
	} else {
		fsp->initial_allocation_size = SMB_ROUNDUP(((SMB_BIG_UINT)file_len),SMB_ROUNDUP_ALLOCATION_SIZE);
	}

	/* Realloc the size of parameters and data we will return */
	params = Realloc(*ppparams, 69);
	if(params == NULL)
		return ERROR_DOS(ERRDOS,ERRnomem);

	*ppparams = params;

	memset((char *)params,'\0',69);

	p = params;
	if (extended_oplock_granted)
		SCVAL(p,0, BATCH_OPLOCK_RETURN);
	else if (LEVEL_II_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(p,0, LEVEL_II_OPLOCK_RETURN);
	else
		SCVAL(p,0,NO_OPLOCK_RETURN);
	
	p += 2;
	SSVAL(p,0,fsp->fnum);
	p += 2;
	if ((create_disposition == FILE_SUPERSEDE) && (smb_action == FILE_WAS_OVERWRITTEN))
		SIVAL(p,0,FILE_WAS_SUPERSEDED);
	else
		SIVAL(p,0,smb_action);
	p += 8;

	/* Create time. */
	c_time = get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn)));

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		c_time &= ~1;
		sbuf.st_atime &= ~1;
		sbuf.st_mtime &= ~1;
		sbuf.st_mtime &= ~1;
	}

	put_long_date(p,c_time);
	p += 8;
	put_long_date(p,sbuf.st_atime); /* access time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* write time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* change time */
	p += 8;
	SIVAL(p,0,fmode); /* File Attributes. */
	p += 4;
	SOFF_T(p, 0, get_allocation_size(fsp,&sbuf));
	p += 8;
	SOFF_T(p,0,file_len);

	DEBUG(5,("call_nt_transact_create: open name = %s\n", fname));

	/* Send the required number of replies */
	send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, params, 69, *ppdata, 0);

	return -1;
}

/****************************************************************************
 Reply to a NT CANCEL request.
****************************************************************************/

int reply_ntcancel(connection_struct *conn,
		   char *inbuf,char *outbuf,int length,int bufsize)
{
	/*
	 * Go through and cancel any pending change notifies.
	 */
	
	int mid = SVAL(inbuf,smb_mid);
	START_PROFILE(SMBntcancel);
	remove_pending_change_notify_requests_by_mid(mid);
	remove_pending_lock_requests_by_mid(mid);
	
	DEBUG(3,("reply_ntcancel: cancel called on mid = %d.\n", mid));

	END_PROFILE(SMBntcancel);
	return(-1);
}

/****************************************************************************
 Reply to an unsolicited SMBNTtranss - just ignore it!
****************************************************************************/

int reply_nttranss(connection_struct *conn,
		   char *inbuf,char *outbuf,int length,int bufsize)
{
	START_PROFILE(SMBnttranss);
	DEBUG(4,("Ignoring nttranss of length %d\n",length));
	END_PROFILE(SMBnttranss);
	return(-1);
}

/****************************************************************************
 Reply to a notify change - queue the request and 
 don't allow a directory to be opened.
****************************************************************************/
static int call_nt_transact_notify_change(connection_struct *conn,
				   char *inbuf, char *outbuf, int length,
				   int bufsize, 
				   char **ppsetup, 
				   char **ppparams, char **ppdata)
{
	char *setup = *ppsetup;
	files_struct *fsp;
	uint32 flags;

	fsp = file_fsp(setup,4);
	flags = IVAL(setup, 0);

	DEBUG(3,("call_nt_transact_notify_change\n"));

	if(!fsp)
		return ERROR_DOS(ERRDOS,ERRbadfid);

	if((!fsp->is_directory) || (conn != fsp->conn))
		return ERROR_DOS(ERRDOS,ERRbadfid);

	if (!change_notify_set(inbuf, fsp, conn, flags))
		return(UNIXERROR(ERRDOS,ERRbadfid));

	DEBUG(3,("call_nt_transact_notify_change: notify change called on directory \
name = %s\n", fsp->fsp_name ));

	return -1;
}

/****************************************************************************
 Reply to an NT transact rename command.
****************************************************************************/

static int call_nt_transact_rename(connection_struct *conn,
				   char *inbuf, char *outbuf, int length, 
                                   int bufsize,
                                   char **ppsetup, char **ppparams, char **ppdata)
{
	char *params = *ppparams;
	pstring new_name;
	files_struct *fsp = file_fsp(params, 0);
	BOOL replace_if_exists = (SVAL(params,2) & RENAME_REPLACE_IF_EXISTS) ? True : False;
	NTSTATUS status;
	uint32 fname_len = MIN((((uint32)IVAL(inbuf,smb_nt_TotalParameterCount)-4)),
				((uint32)sizeof(new_name)-1));

	CHECK_FSP(fsp, conn);
	StrnCpy(new_name,params+4,fname_len);
	new_name[fname_len] = '\0';

	status = rename_internals(conn, fsp->fsp_name,
                             new_name, replace_if_exists);
	if (!NT_STATUS_IS_OK(status))
		return ERROR_NT(status);

	/*
	 * Rename was successful.
	 */
	send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, NULL, 0, NULL, 0);

	DEBUG(3,("nt transact rename from = %s, to = %s succeeded.\n", 
		fsp->fsp_name, new_name));

	/*
	 * Win2k needs a changenotify request response before it will
	 * update after a rename..
	 */

	process_pending_change_notify_queue((time_t)0);

	return -1;
}

/******************************************************************************
 Fake up a completely empty SD.
*******************************************************************************/

static size_t get_null_nt_acl(TALLOC_CTX *mem_ctx, SEC_DESC **ppsd)
{
	extern DOM_SID global_sid_World;
	size_t sd_size;

	*ppsd = make_standard_sec_desc( mem_ctx, &global_sid_World, &global_sid_World, NULL, &sd_size);
	if(!*ppsd) {
		DEBUG(0,("get_null_nt_acl: Unable to malloc space for security descriptor.\n"));
		sd_size = 0;
	}
 
	return sd_size;
}

/****************************************************************************
 Reply to query a security descriptor - currently this is not implemented (it
 is planned to be though). Right now it just returns the same thing NT would
 when queried on a FAT filesystem. JRA.
****************************************************************************/

static int call_nt_transact_query_security_desc(connection_struct *conn,
                                                char *inbuf, char *outbuf, 
                                                int length, int bufsize, 
                                                char **ppsetup, char **ppparams, char **ppdata)
{
  uint32 max_data_count = IVAL(inbuf,smb_nt_MaxDataCount);
  char *params = *ppparams;
  char *data = *ppdata;
  prs_struct pd;
  SEC_DESC *psd = NULL;
  size_t sd_size;
  TALLOC_CTX *mem_ctx;

  files_struct *fsp = file_fsp(params,0);

  if(!fsp)
    return ERROR_DOS(ERRDOS,ERRbadfid);

  DEBUG(3,("call_nt_transact_query_security_desc: file = %s\n", fsp->fsp_name ));

  params = Realloc(*ppparams, 4);
  if(params == NULL)
    return ERROR_DOS(ERRDOS,ERRnomem);

  *ppparams = params;

  if ((mem_ctx = talloc_init()) == NULL) {
    DEBUG(0,("call_nt_transact_query_security_desc: talloc_init failed.\n"));
    return ERROR_DOS(ERRDOS,ERRnomem);
  }

  /*
   * Get the permissions to return.
   */

  if (!lp_nt_acl_support(SNUM(conn)))
    sd_size = get_null_nt_acl(mem_ctx, &psd);
  else
    sd_size = conn->vfs_ops.fget_nt_acl(fsp, fsp->fd, &psd);

  if (sd_size == 0) {
    talloc_destroy(mem_ctx);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  DEBUG(3,("call_nt_transact_query_security_desc: sd_size = %d.\n",(int)sd_size));

  SIVAL(params,0,(uint32)sd_size);

  if(max_data_count < sd_size) {

    send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_BUFFER_TOO_SMALL,
                    params, 4, *ppdata, 0);
    talloc_destroy(mem_ctx);
    return -1;
  }

  /*
   * Allocate the data we will point this at.
   */

  data = Realloc(*ppdata, sd_size);
  if(data == NULL) {
    talloc_destroy(mem_ctx);
    return ERROR_DOS(ERRDOS,ERRnomem);
  }

  *ppdata = data;

  memset(data, '\0', sd_size);

  /*
   * Init the parse struct we will marshall into.
   */

  prs_init(&pd, 0, mem_ctx, MARSHALL);

  /*
   * Setup the prs_struct to point at the memory we just
   * allocated.
   */

  prs_give_memory( &pd, data, (uint32)sd_size, False);

  /*
   * Finally, linearize into the outgoing buffer.
   */

  if(!sec_io_desc( "sd data", &psd, &pd, 1)) {
    DEBUG(0,("call_nt_transact_query_security_desc: Error in marshalling \
security descriptor.\n"));
    /*
     * Return access denied for want of a better error message..
     */ 
    talloc_destroy(mem_ctx);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  /*
   * Now we can delete the security descriptor.
   */

  talloc_destroy(mem_ctx);

  send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, params, 4, data, (int)sd_size);
  return -1;
}

/****************************************************************************
 Reply to set a security descriptor. Map to UNIX perms.
****************************************************************************/

static int call_nt_transact_set_security_desc(connection_struct *conn,
									char *inbuf, char *outbuf, int length,
									int bufsize, char **ppsetup, 
									char **ppparams, char **ppdata)
{
	uint32 total_parameter_count = IVAL(inbuf, smb_nts_TotalParameterCount);
	char *params= *ppparams;
	char *data = *ppdata;
	uint32 total_data_count = (uint32)IVAL(inbuf, smb_nts_TotalDataCount);
	files_struct *fsp = NULL;
	uint32 security_info_sent = 0;
	int error_class;
	uint32 error_code;

	if(total_parameter_count < 8)
		return ERROR_DOS(ERRDOS,ERRbadfunc);

	if((fsp = file_fsp(params,0)) == NULL)
		return ERROR_DOS(ERRDOS,ERRbadfid);

	if(!lp_nt_acl_support(SNUM(conn)))
		goto done;

	security_info_sent = IVAL(params,4);

	DEBUG(3,("call_nt_transact_set_security_desc: file = %s, sent 0x%x\n", fsp->fsp_name,
		(unsigned int)security_info_sent ));

	if (total_data_count == 0)
		return ERROR_DOS(ERRDOS, ERRnoaccess);

	if (!set_sd( fsp, data, total_data_count, security_info_sent, &error_class, &error_code))
		return ERROR_DOS(error_class, error_code);

  done:

	send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, NULL, 0, NULL, 0);
	return -1;
}
   
/****************************************************************************
 Reply to IOCTL.
****************************************************************************/

static int call_nt_transact_ioctl(connection_struct *conn,
				char *inbuf, char *outbuf, int length,
				int bufsize, 
				char **ppsetup, int setup_count,
				char **ppparams, int parameter_count,
				char **ppdata, int data_count)
{
	unsigned fnum, control;
	static BOOL logged_message;
 
	if (setup_count != 8) {
		DEBUG(3,("call_nt_transact_ioctl: invalid setup count %d\n", setup_count));
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}
 
	fnum = SVAL(*ppsetup, 4);
	control = IVAL(*ppsetup, 0);
 
	DEBUG(6,("call_nt_transact_ioctl: fnum=%d control=0x%x\n",
		fnum, control));
 
	switch (control) {
	case NTIOCTL_SET_SPARSE:
		/* pretend this succeeded - tho strictly we should
			mark the file sparse (if the local fs supports it)
			so we can know if we need to pre-allocate or not */
		send_nt_replies(inbuf, outbuf, bufsize, NT_STATUS_OK, NULL, 0, NULL, 0);
		return -1;
 
	default:
		if (!logged_message) {
			logged_message = True; /* Only print this once... */
			DEBUG(3,("call_nt_transact_ioctl(0x%x): Currently not implemented.\n",
				control));
		}
	}
 
	return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
}
   
/****************************************************************************
 Reply to a SMBNTtrans.
****************************************************************************/

int reply_nttrans(connection_struct *conn,
		  char *inbuf,char *outbuf,int length,int bufsize)
{
	int  outsize = 0;
#if 0 /* Not used. */
	uint16 max_setup_count = CVAL(inbuf, smb_nt_MaxSetupCount);
	uint32 max_parameter_count = IVAL(inbuf, smb_nt_MaxParameterCount);
	uint32 max_data_count = IVAL(inbuf,smb_nt_MaxDataCount);
#endif /* Not used. */
	uint32 total_parameter_count = IVAL(inbuf, smb_nt_TotalParameterCount);
	uint32 total_data_count = IVAL(inbuf, smb_nt_TotalDataCount);
	uint32 parameter_count = IVAL(inbuf,smb_nt_ParameterCount);
	uint32 parameter_offset = IVAL(inbuf,smb_nt_ParameterOffset);
	uint32 data_count = IVAL(inbuf,smb_nt_DataCount);
	uint32 data_offset = IVAL(inbuf,smb_nt_DataOffset);
	uint16 setup_count = 2*CVAL(inbuf,smb_nt_SetupCount); /* setup count is in *words* */
	uint16 function_code = SVAL( inbuf, smb_nt_Function);
	char *params = NULL, *data = NULL, *setup = NULL;
	uint32 num_params_sofar, num_data_sofar;
	START_PROFILE(SMBnttrans);

	if(global_oplock_break &&
			((function_code == NT_TRANSACT_CREATE) ||
			 (function_code == NT_TRANSACT_RENAME))) {
		/*
		 * Queue this open message as we are the process of an oplock break.
		 */

		DEBUG(2,("reply_nttrans: queueing message code 0x%x \
due to being in oplock break state.\n", (unsigned int)function_code ));

		push_oplock_pending_smb_message( inbuf, length);
		END_PROFILE(SMBnttrans);
		return -1;
	}

	if (IS_IPC(conn) && (function_code != NT_TRANSACT_CREATE)) {
		END_PROFILE(SMBnttrans);
		return ERROR_DOS(ERRSRV,ERRaccess);
	}

	outsize = set_message(outbuf,0,0,True);

	/* 
	 * All nttrans messages we handle have smb_wct == 19 + setup_count.
	 * Ensure this is so as a sanity check.
	 */

	if(CVAL(inbuf, smb_wct) != 19 + (setup_count/2)) {
		DEBUG(2,("Invalid smb_wct %d in nttrans call (should be %d)\n",
			CVAL(inbuf, smb_wct), 19 + (setup_count/2)));
		goto bad_param;
	}
    
	/* Allocate the space for the setup, the maximum needed parameters and data */

	if(setup_count > 0)
		setup = (char *)malloc(setup_count);
	if (total_parameter_count > 0)
		params = (char *)malloc(total_parameter_count);
	if (total_data_count > 0)
		data = (char *)malloc(total_data_count);
 
	if ((total_parameter_count && !params)  || (total_data_count && !data) ||
				(setup_count && !setup)) {
		SAFE_FREE(setup);
		SAFE_FREE(params);
		SAFE_FREE(data);
		DEBUG(0,("reply_nttrans : Out of memory\n"));
		END_PROFILE(SMBnttrans);
		return ERROR_DOS(ERRDOS,ERRnomem);
	}

	/* Copy the param and data bytes sent with this request into the params buffer */
	num_params_sofar = parameter_count;
	num_data_sofar = data_count;

	if (parameter_count > total_parameter_count || data_count > total_data_count)
		goto bad_param;

	if(setup) {
		DEBUG(10,("reply_nttrans: setup_count = %d\n", setup_count));
		if ((smb_nt_SetupStart + setup_count < smb_nt_SetupStart) ||
				(smb_nt_SetupStart + setup_count < setup_count))
			goto bad_param;
		if (smb_nt_SetupStart + setup_count > length)
			goto bad_param;

		memcpy( setup, &inbuf[smb_nt_SetupStart], setup_count);
		dump_data(10, setup, setup_count);
	}
	if(params) {
		DEBUG(10,("reply_nttrans: parameter_count = %d\n", parameter_count));
		if ((parameter_offset + parameter_count < parameter_offset) ||
				(parameter_offset + parameter_count < parameter_count))
			goto bad_param;
		if (smb_base(inbuf) + parameter_offset + parameter_count > inbuf + length)
			goto bad_param;

		memcpy( params, smb_base(inbuf) + parameter_offset, parameter_count);
		dump_data(10, params, parameter_count);
	}
	if(data) {
		DEBUG(10,("reply_nttrans: data_count = %d\n",data_count));
		if ((data_offset + data_count < data_offset) || (data_offset + data_count < data_count))
			goto bad_param;
		if (smb_base(inbuf) + data_offset + data_count > inbuf + length)
			goto bad_param;

		memcpy( data, smb_base(inbuf) + data_offset, data_count);
		dump_data(10, data, data_count);
	}

	if(num_data_sofar < total_data_count || num_params_sofar < total_parameter_count) {
		/* We need to send an interim response then receive the rest
			of the parameter/data bytes */
		outsize = set_message(outbuf,0,0,True);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_nttrans: send_smb failed.");

		while( num_data_sofar < total_data_count || num_params_sofar < total_parameter_count) {
			BOOL ret;
			uint32 parameter_displacement;
			uint32 data_displacement;

			ret = receive_next_smb(inbuf,bufsize,SMB_SECONDARY_WAIT);

			if((ret && (CVAL(inbuf, smb_com) != SMBnttranss)) || !ret) {
				outsize = set_message(outbuf,0,0,True);
				if(ret) {
					DEBUG(0,("reply_nttrans: Invalid secondary nttrans packet\n"));
				} else {
					DEBUG(0,("reply_nttrans: %s in getting secondary nttrans response.\n",
						(smb_read_error == READ_ERROR) ? "error" : "timeout" ));
				}
				goto bad_param;
			}
      
			/* Revise total_params and total_data in case they have changed downwards */
			if (IVAL(inbuf, smb_nts_TotalParameterCount) < total_parameter_count)
				total_parameter_count = IVAL(inbuf, smb_nts_TotalParameterCount);
			if (IVAL(inbuf, smb_nts_TotalDataCount) < total_data_count)
				total_data_count = IVAL(inbuf, smb_nts_TotalDataCount);

			parameter_count = IVAL(inbuf,smb_nts_ParameterCount);
			parameter_offset = IVAL(inbuf, smb_nts_ParameterOffset);
			parameter_displacement = IVAL(inbuf, smb_nts_ParameterDisplacement);
			num_params_sofar += parameter_count;

			data_count = IVAL(inbuf, smb_nts_DataCount);
			data_displacement = IVAL(inbuf, smb_nts_DataDisplacement);
			data_offset = IVAL(inbuf, smb_nts_DataOffset);
			num_data_sofar += data_count;

			if (num_params_sofar > total_parameter_count || num_data_sofar > total_data_count) {
				DEBUG(0,("reply_nttrans2: data overflow in secondary nttrans packet"));
				goto bad_param;
			}

			if (parameter_count) {
				if (parameter_displacement + parameter_count >= total_parameter_count)
					goto bad_param;
				if ((parameter_displacement + parameter_count < parameter_displacement) ||
						(parameter_displacement + parameter_count < parameter_count))
					goto bad_param;
				if (smb_base(inbuf) + parameter_offset + parameter_count >= inbuf + bufsize)
					goto bad_param;
				if (params + parameter_displacement < params)
					goto bad_param;

				memcpy( &params[parameter_displacement], smb_base(inbuf) + parameter_offset, parameter_count);
			}

			if (data_count) {
				if (data_displacement + data_count >= total_data_count)
					goto bad_param;
				if ((data_displacement + data_count < data_displacement) ||
						(data_displacement + data_count < data_count))
					goto bad_param;
				if (smb_base(inbuf) + data_offset + data_count >= inbuf + bufsize)
					goto bad_param;
				if (data + data_displacement < data)
					goto bad_param;

				memcpy( &data[data_displacement], smb_base(inbuf)+ data_offset, data_count);
			}
		}
	}

	if (Protocol >= PROTOCOL_NT1)
		SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | FLAGS2_IS_LONG_NAME);

	/* Now we must call the relevant NT_TRANS function */
	switch(function_code) {
		case NT_TRANSACT_CREATE:
			START_PROFILE_NESTED(NT_transact_create);
			outsize = call_nt_transact_create(conn, inbuf, outbuf, length, bufsize, 
					&setup, &params, &data);
			END_PROFILE_NESTED(NT_transact_create);
			break;
		case NT_TRANSACT_IOCTL:
			START_PROFILE_NESTED(NT_transact_ioctl);
			outsize = call_nt_transact_ioctl(conn, inbuf, outbuf,
					length, bufsize, 
					&setup, setup_count,
					&params, parameter_count,
					&data, data_count);
			END_PROFILE_NESTED(NT_transact_ioctl);
			break;
		case NT_TRANSACT_SET_SECURITY_DESC:
			START_PROFILE_NESTED(NT_transact_set_security_desc);
			outsize = call_nt_transact_set_security_desc(conn, inbuf, outbuf, 
					length, bufsize, 
					&setup, &params, &data);
			END_PROFILE_NESTED(NT_transact_set_security_desc);
			break;
		case NT_TRANSACT_NOTIFY_CHANGE:
			START_PROFILE_NESTED(NT_transact_notify_change);
			outsize = call_nt_transact_notify_change(conn, inbuf, outbuf, 
					length, bufsize, 
					&setup, &params, &data);
			END_PROFILE_NESTED(NT_transact_notify_change);
			break;
		case NT_TRANSACT_RENAME:
			START_PROFILE_NESTED(NT_transact_rename);
			outsize = call_nt_transact_rename(conn, inbuf, outbuf, length, 
					bufsize, 
					&setup, &params, &data);
			END_PROFILE_NESTED(NT_transact_rename);
			break;

		case NT_TRANSACT_QUERY_SECURITY_DESC:
			START_PROFILE_NESTED(NT_transact_query_security_desc);
			outsize = call_nt_transact_query_security_desc(conn, inbuf, outbuf, 
					length, bufsize, 
					&setup, &params, &data);
			END_PROFILE_NESTED(NT_transact_query_security_desc);
			break;
		default:
			/* Error in request */
			DEBUG(0,("reply_nttrans: Unknown request %d in nttrans call\n", function_code));
			SAFE_FREE(setup);
			SAFE_FREE(params);
			SAFE_FREE(data);
			END_PROFILE(SMBnttrans);
			return ERROR_DOS(ERRSRV,ERRerror);
	}

	/* As we do not know how many data packets will need to be
		returned here the various call_nt_transact_xxxx calls
		must send their own. Thus a call_nt_transact_xxxx routine only
		returns a value other than -1 when it wants to send
		an error packet. 
	*/

	SAFE_FREE(setup);
	SAFE_FREE(params);
	SAFE_FREE(data);
	END_PROFILE(SMBnttrans);
	return outsize; /* If a correct response was needed the call_nt_transact_xxxx 
				calls have already sent it. If outsize != -1 then it is
				returning an error packet. */

 bad_param:

	SAFE_FREE(params);
	SAFE_FREE(data);
	SAFE_FREE(setup);
	END_PROFILE(SMBnttrans);
	return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
}
