/* 
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2004.

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
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/

#include "includes.h"

/* look in server.c for some explanation of these variables */
extern int Protocol;
extern int max_send;
extern int max_recv;
extern char magic_char;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;
extern int global_oplock_break;
unsigned int smb_echo_count = 0;

extern BOOL global_encrypted_passwords_negotiated;

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption). '\\' *may* be the second byte in a multibyte char
 set.
****************************************************************************/

NTSTATUS check_path_syntax(pstring destname, const pstring srcname)
{
	char *d = destname;
	const char *s = srcname;
	NTSTATUS ret = NT_STATUS_OK;

	while (*s) {
		if (IS_DIRECTORY_SEP(*s)) {
			/*
			 * Safe to assume is not the second part of a mb char as this is handled below.
			 */
			/* Eat multiple '/' or '\\' */
			while (IS_DIRECTORY_SEP(*s)) {
				s++;
			}
			if ((s[0] == '.') && (s[1] == '\0')) {
				ret = NT_STATUS_OBJECT_NAME_INVALID;
				break;
			}
			if ((d != destname) && (*s != '\0')) {
				/* We only care about non-leading or trailing '/' or '\\' */
				*d++ = '/';
			}
		} else if ((s[0] == '.') && (s[1] == '.') && (IS_DIRECTORY_SEP(s[2]) || s[2] == '\0')) {
			/* Uh oh - "../" or "..\\"  or "..\0" ! */

			/*
			 * No mb char starts with '.' so we're safe checking the directory separator here.
			 */

			/* If we just added a '/', delete it. */

			if ((d > destname) && (*(d-1) == '/')) {
				*(d-1) = '\0';
				if (d == (destname + 1)) {
					d--;
				} else {
					d -= 2;
				}
			}
			/* Are we at the start ? Can't go back further if so. */
			if (d == destname) {
				ret = NT_STATUS_OBJECT_PATH_SYNTAX_BAD;
				break;
			}
			/* Go back one level... */
			/* We know this is safe as '/' cannot be part of a mb sequence. */
			/* NOTE - if this assumption is invalid we are not in good shape... */
			while (d > destname) {
				if (*d == '/')
					break;
				d--;
			}
			s += 3;
		} else if ((s[0] == '.') && (IS_DIRECTORY_SEP(s[1]) || (s[1] == '\0'))) {

			/*
			 * No mb char starts with '.' so we're safe checking the directory separator here.
			 */

			/* "./" or ".\\" fails with a different error depending on where it is... */

			if (s == srcname) {
				ret = NT_STATUS_OBJECT_NAME_INVALID;
				break;
			} else {
				if (s[1] != '\0' && s[2] == '\0') {
					ret = NT_STATUS_INVALID_PARAMETER;
					break;
				}
				ret = NT_STATUS_OBJECT_PATH_NOT_FOUND;
				break;
			}
			s++;
		} else {
			if (!(*s & 0x80)) {
				*d++ = *s++;
			} else {
				switch(next_mb_char_size(s)) {
					case 4:
						*d++ = *s++;
					case 3:
						*d++ = *s++;
					case 2:
						*d++ = *s++;
					case 1:
						*d++ = *s++;
						break;
					default:
						DEBUG(0,("check_path_syntax: character length assumptions invalid !\n"));
						*d = '\0';
						return NT_STATUS_INVALID_PARAMETER;
				}
			}
		}
	}
	*d = '\0';
	return ret;
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
****************************************************************************/

size_t srvstr_get_path(char *inbuf, char *dest, const char *src, size_t dest_len, size_t src_len, int flags, NTSTATUS *err)
{
	pstring tmppath;
	char *tmppath_ptr = tmppath;
	size_t ret;
#ifdef DEVELOPER
	SMB_ASSERT(dest_len == sizeof(pstring));
#endif

	if (src_len == 0) {
		ret = srvstr_pull_buf( inbuf, tmppath_ptr, src, dest_len, flags);
	} else {
		ret = srvstr_pull( inbuf, tmppath_ptr, src, dest_len, src_len, flags);
	}
	*err = check_path_syntax(dest, tmppath);
	return ret;
}

/****************************************************************************
 Reply to a special message.
****************************************************************************/

int reply_special(char *inbuf,char *outbuf)
{
	int outsize = 4;
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	fstring name1,name2;
	char name_type = 0;
	
	static BOOL already_got_session = False;

	*name1 = *name2 = 0;
	
	memset(outbuf,'\0',smb_size);

	smb_setlen(outbuf,0);
	
	switch (msg_type) {
	case 0x81: /* session request */
		
		if (already_got_session) {
			exit_server("multiple session request not permitted");
		}
		
		SCVAL(outbuf,0,0x82);
		SCVAL(outbuf,3,0);
		if (name_len(inbuf+4) > 50 || 
		    name_len(inbuf+4 + name_len(inbuf + 4)) > 50) {
			DEBUG(0,("Invalid name length in session request\n"));
			return(0);
		}
		name_extract(inbuf,4,name1);
		name_type = name_extract(inbuf,4 + name_len(inbuf + 4),name2);
		DEBUG(2,("netbios connect: name1=%s name2=%s\n",
			 name1,name2));      

		set_local_machine_name(name1, True);
		set_remote_machine_name(name2, True);

		DEBUG(2,("netbios connect: local=%s remote=%s, name type = %x\n",
			 get_local_machine_name(), get_remote_machine_name(),
			 name_type));

		if (name_type == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			SCVAL(outbuf, 0,0x83);
			break;
		}

		/* only add the client's machine name to the list
		   of possibly valid usernames if we are operating
		   in share mode security */
		if (lp_security() == SEC_SHARE) {
			add_session_user(get_remote_machine_name());
		}

		reload_services(True);
		reopen_logs();

		claim_connection(NULL,"",0,True,FLAG_MSG_GENERAL|FLAG_MSG_SMBD);

		already_got_session = True;
		break;
		
	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		SCVAL(outbuf,0,SMBkeepalive);
		SCVAL(outbuf,3,0);
		break;
		
	case 0x82: /* positive session response */
	case 0x83: /* negative session response */
	case 0x84: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;
		
	case SMBkeepalive: /* session keepalive */
	default:
		return(0);
	}
	
	DEBUG(5,("init msg_type=0x%x msg_flags=0x%x\n",
		    msg_type, msg_flags));
	
	return(outsize);
}

/****************************************************************************
 Reply to a tcon.
****************************************************************************/

int reply_tcon(connection_struct *conn,
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	const char *service;
	pstring service_buf;
	pstring password;
	pstring dev;
	int outsize = 0;
	uint16 vuid = SVAL(inbuf,smb_uid);
	int pwlen=0;
	NTSTATUS nt_status;
	char *p;
	DATA_BLOB password_blob;
	
	START_PROFILE(SMBtcon);

	*service_buf = *password = *dev = 0;

	p = smb_buf(inbuf)+1;
	p += srvstr_pull_buf(inbuf, service_buf, p, sizeof(service_buf), STR_TERMINATE) + 1;
	pwlen = srvstr_pull_buf(inbuf, password, p, sizeof(password), STR_TERMINATE) + 1;
	p += pwlen;
	p += srvstr_pull_buf(inbuf, dev, p, sizeof(dev), STR_TERMINATE) + 1;

	p = strrchr_m(service_buf,'\\');
	if (p) {
		service = p+1;
	} else {
		service = service_buf;
	}

	password_blob = data_blob(password, pwlen+1);

	conn = make_connection(service,password_blob,dev,vuid,&nt_status);

	data_blob_clear_free(&password_blob);
  
	if (!conn) {
		END_PROFILE(SMBtcon);
		return ERROR_NT(nt_status);
	}
  
	outsize = set_message(outbuf,2,0,True);
	SSVAL(outbuf,smb_vwv0,max_recv);
	SSVAL(outbuf,smb_vwv1,conn->cnum);
	SSVAL(outbuf,smb_tid,conn->cnum);
  
	DEBUG(3,("tcon service=%s cnum=%d\n", 
		 service, conn->cnum));
  
	END_PROFILE(SMBtcon);
	return(outsize);
}

/****************************************************************************
 Reply to a tcon and X.
****************************************************************************/

int reply_tcon_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	fstring service;
	DATA_BLOB password;

	/* what the cleint thinks the device is */
	fstring client_devicetype;
	/* what the server tells the client the share represents */
	const char *server_devicetype;
	NTSTATUS nt_status;
	uint16 vuid = SVAL(inbuf,smb_uid);
	int passlen = SVAL(inbuf,smb_vwv3);
	pstring path;
	char *p, *q;
	extern BOOL global_encrypted_passwords_negotiated;
	
	START_PROFILE(SMBtconX);	

	*service = *client_devicetype = 0;

	/* we might have to close an old one */
	if ((SVAL(inbuf,smb_vwv2) & 0x1) && conn) {
		close_cnum(conn,vuid);
	}

	if (passlen > MAX_PASS_LEN) {
		return ERROR_DOS(ERRDOS,ERRbuftoosmall);
	}
 
	if (global_encrypted_passwords_negotiated) {
		password = data_blob(smb_buf(inbuf),passlen);
	} else {
		password = data_blob(smb_buf(inbuf),passlen+1);
		/* Ensure correct termination */
		password.data[passlen]=0;    
	}

	p = smb_buf(inbuf) + passlen;
	p += srvstr_pull_buf(inbuf, path, p, sizeof(path), STR_TERMINATE);

	/*
	 * the service name can be either: \\server\share
	 * or share directly like on the DELL PowerVault 705
	 */
	if (*path=='\\') {	
		q = strchr_m(path+2,'\\');
		if (!q) {
			END_PROFILE(SMBtconX);
			return(ERROR_DOS(ERRDOS,ERRnosuchshare));
		}
		fstrcpy(service,q+1);
	}
	else
		fstrcpy(service,path);
		
	p += srvstr_pull(inbuf, client_devicetype, p, sizeof(client_devicetype), 6, STR_ASCII);

	DEBUG(4,("Client requested device type [%s] for share [%s]\n", client_devicetype, service));

	conn = make_connection(service,password,client_devicetype,vuid,&nt_status);
	
	data_blob_clear_free(&password);

	if (!conn) {
		END_PROFILE(SMBtconX);
		return ERROR_NT(nt_status);
	}

	if ( IS_IPC(conn) )
		server_devicetype = "IPC";
	else if ( IS_PRINT(conn) )
		server_devicetype = "LPT1:";
	else 
		server_devicetype = "A:";

	if (Protocol < PROTOCOL_NT1) {
		set_message(outbuf,2,0,True);
		p = smb_buf(outbuf);
		p += srvstr_push(outbuf, p, server_devicetype, -1, 
				 STR_TERMINATE|STR_ASCII);
		set_message_end(outbuf,p);
	} else {
		/* NT sets the fstype of IPC$ to the null string */
		const char *fstype = IS_IPC(conn) ? "" : lp_fstype(SNUM(conn));
		
		set_message(outbuf,3,0,True);

		p = smb_buf(outbuf);
		p += srvstr_push(outbuf, p, server_devicetype, -1, 
				 STR_TERMINATE|STR_ASCII);
		p += srvstr_push(outbuf, p, fstype, -1, 
				 STR_TERMINATE);
		
		set_message_end(outbuf,p);
		
		/* what does setting this bit do? It is set by NT4 and
		   may affect the ability to autorun mounted cdroms */
		SSVAL(outbuf, smb_vwv2, SMB_SUPPORT_SEARCH_BITS|
				(lp_csc_policy(SNUM(conn)) << 2));
		
		init_dfsroot(conn, inbuf, outbuf);
	}

  
	DEBUG(3,("tconX service=%s \n",
		 service));
  
	/* set the incoming and outgoing tid to the just created one */
	SSVAL(inbuf,smb_tid,conn->cnum);
	SSVAL(outbuf,smb_tid,conn->cnum);

	END_PROFILE(SMBtconX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to an unknown type.
****************************************************************************/

int reply_unknown(char *inbuf,char *outbuf)
{
	int type;
	type = CVAL(inbuf,smb_com);
  
	DEBUG(0,("unknown command type (%s): type=%d (0x%X)\n",
		 smb_fn_name(type), type, type));
  
	return(ERROR_DOS(ERRSRV,ERRunknownsmb));
}

/****************************************************************************
 Reply to an ioctl.
****************************************************************************/

int reply_ioctl(connection_struct *conn,
		char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	uint16 device     = SVAL(inbuf,smb_vwv1);
	uint16 function   = SVAL(inbuf,smb_vwv2);
	uint32 ioctl_code = (device << 16) + function;
	int replysize, outsize;
	char *p;
	START_PROFILE(SMBioctl);

	DEBUG(4, ("Received IOCTL (code 0x%x)\n", ioctl_code));

	switch (ioctl_code) {
	    case IOCTL_QUERY_JOB_INFO:
		replysize = 32;
		break;
	    default:
		END_PROFILE(SMBioctl);
		return(ERROR_DOS(ERRSRV,ERRnosupport));
	}

	outsize = set_message(outbuf,8,replysize+1,True);
	SSVAL(outbuf,smb_vwv1,replysize); /* Total data bytes returned */
	SSVAL(outbuf,smb_vwv5,replysize); /* Data bytes this buffer */
	SSVAL(outbuf,smb_vwv6,52);        /* Offset to data */
	p = smb_buf(outbuf) + 1;          /* Allow for alignment */

	switch (ioctl_code) {
		case IOCTL_QUERY_JOB_INFO:		    
		{
			files_struct *fsp = file_fsp(inbuf,smb_vwv0);
			if (!fsp) {
				END_PROFILE(SMBioctl);
				return(UNIXERROR(ERRDOS,ERRbadfid));
			}
			SSVAL(p,0,fsp->rap_print_jobid);             /* Job number */
			srvstr_push(outbuf, p+2, global_myname(), 15, STR_TERMINATE|STR_ASCII);
			srvstr_push(outbuf, p+18, lp_servicename(SNUM(conn)), 13, STR_TERMINATE|STR_ASCII);
			break;
		}
	}

	END_PROFILE(SMBioctl);
	return outsize;
}

/****************************************************************************
 Reply to a chkpth.
****************************************************************************/

int reply_chkpth(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	int mode;
	pstring name;
	BOOL ok = False;
	BOOL bad_path = False;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;

	START_PROFILE(SMBchkpth);

	srvstr_get_path(inbuf, name, smb_buf(inbuf) + 1, sizeof(name), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBchkpth);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);

	unix_convert(name,conn,0,&bad_path,&sbuf);

	mode = SVAL(inbuf,smb_vwv0);

	if (check_name(name,conn)) {
		if (VALID_STAT(sbuf) || SMB_VFS_STAT(conn,name,&sbuf) == 0)
			if (!(ok = S_ISDIR(sbuf.st_mode))) {
				END_PROFILE(SMBchkpth);
				return ERROR_BOTH(NT_STATUS_NOT_A_DIRECTORY,ERRDOS,ERRbadpath);
			}
	}

	if (!ok) {
		/* We special case this - as when a Windows machine
			is parsing a path is steps through the components
			one at a time - if a component fails it expects
			ERRbadpath, not ERRbadfile.
		*/
		if(errno == ENOENT) {
			/*
			 * Windows returns different error codes if
			 * the parent directory is valid but not the
			 * last component - it returns NT_STATUS_OBJECT_NAME_NOT_FOUND
			 * for that case and NT_STATUS_OBJECT_PATH_NOT_FOUND
			 * if the path is invalid.
			 */
			if (bad_path) {
				END_PROFILE(SMBchkpth);
				return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
			} else {
				END_PROFILE(SMBchkpth);
				return ERROR_NT(NT_STATUS_OBJECT_NAME_NOT_FOUND);
			}
		} else if (errno == ENOTDIR) {
			END_PROFILE(SMBchkpth);
			return ERROR_NT(NT_STATUS_NOT_A_DIRECTORY);
		}

		END_PROFILE(SMBchkpth);
		return(UNIXERROR(ERRDOS,ERRbadpath));
	}

	outsize = set_message(outbuf,0,0,True);

	DEBUG(3,("chkpth %s mode=%d\n", name, mode));

	END_PROFILE(SMBchkpth);
	return(outsize);
}

/****************************************************************************
 Reply to a getatr.
****************************************************************************/

int reply_getatr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int outsize = 0;
	SMB_STRUCT_STAT sbuf;
	BOOL ok = False;
	int mode=0;
	SMB_OFF_T size=0;
	time_t mtime=0;
	BOOL bad_path = False;
	char *p;
	NTSTATUS status;

	START_PROFILE(SMBgetatr);

	p = smb_buf(inbuf) + 1;
	p += srvstr_get_path(inbuf, fname, p, sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBgetatr);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);
  
	/* dos smetimes asks for a stat of "" - it returns a "hidden directory"
		under WfWg - weird! */
	if (! (*fname)) {
		mode = aHIDDEN | aDIR;
		if (!CAN_WRITE(conn))
			mode |= aRONLY;
		size = 0;
		mtime = 0;
		ok = True;
	} else {
		unix_convert(fname,conn,0,&bad_path,&sbuf);
		if (check_name(fname,conn)) {
			if (VALID_STAT(sbuf) || SMB_VFS_STAT(conn,fname,&sbuf) == 0) {
				mode = dos_mode(conn,fname,&sbuf);
				size = sbuf.st_size;
				mtime = sbuf.st_mtime;
				if (mode & aDIR)
					size = 0;
				ok = True;
			} else {
				DEBUG(3,("stat of %s failed (%s)\n",fname,strerror(errno)));
			}
		}
	}
  
	if (!ok) {
		END_PROFILE(SMBgetatr);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS,ERRbadfile);
	}
 
	outsize = set_message(outbuf,10,0,True);

	SSVAL(outbuf,smb_vwv0,mode);
	if(lp_dos_filetime_resolution(SNUM(conn)) )
		put_dos_date3(outbuf,smb_vwv1,mtime & ~1);
	else
		put_dos_date3(outbuf,smb_vwv1,mtime);
	SIVAL(outbuf,smb_vwv3,(uint32)size);

	if (Protocol >= PROTOCOL_NT1)
		SSVAL(outbuf,smb_flg2,SVAL(outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
  
	DEBUG( 3, ( "getatr name=%s mode=%d size=%d\n", fname, mode, (uint32)size ) );
  
	END_PROFILE(SMBgetatr);
	return(outsize);
}

/****************************************************************************
 Reply to a setatr.
****************************************************************************/

int reply_setatr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int outsize = 0;
	BOOL ok=False;
	int mode;
	time_t mtime;
	SMB_STRUCT_STAT sbuf;
	BOOL bad_path = False;
	char *p;
	NTSTATUS status;

	START_PROFILE(SMBsetatr);

	p = smb_buf(inbuf) + 1;
	p += srvstr_get_path(inbuf, fname, p, sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBsetatr);
		return ERROR_NT(status);
	}

	unix_convert(fname,conn,0,&bad_path,&sbuf);

	mode = SVAL(inbuf,smb_vwv0);
	mtime = make_unix_date3(inbuf+smb_vwv1);
  
	if (mode != FILE_ATTRIBUTE_NORMAL) {
		if (VALID_STAT_OF_DIR(sbuf))
			mode |= aDIR;
		else
			mode &= ~aDIR;

		if (check_name(fname,conn)) {
			ok = (file_set_dosmode(conn,fname,mode,NULL) == 0);
		}
	} else {
		ok = True;
	}

	if (ok)
		ok = set_filetime(conn,fname,mtime);
  
	if (!ok) {
		END_PROFILE(SMBsetatr);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnoaccess);
	}
 
	outsize = set_message(outbuf,0,0,True);
  
	DEBUG( 3, ( "setatr name=%s mode=%d\n", fname, mode ) );
  
	END_PROFILE(SMBsetatr);
	return(outsize);
}

/****************************************************************************
 Reply to a dskattr.
****************************************************************************/

int reply_dskattr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	SMB_BIG_UINT dfree,dsize,bsize;
	START_PROFILE(SMBdskattr);

	SMB_VFS_DISK_FREE(conn,".",True,&bsize,&dfree,&dsize);
  
	outsize = set_message(outbuf,5,0,True);
	
	if (Protocol <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers 

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (total_space+63*512) / (64*512);
		dfree = (free_space+63*512) / (64*512);
		
		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,bsize/512);
		SSVAL(outbuf,smb_vwv2,512);
		SSVAL(outbuf,smb_vwv3,dfree);
	}

	DEBUG(3,("dskattr dfree=%d\n", (unsigned int)dfree));

	END_PROFILE(SMBdskattr);
	return(outsize);
}

/****************************************************************************
 Reply to a search.
 Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/

int reply_search(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring mask;
	pstring directory;
	pstring fname;
	SMB_OFF_T size;
	int mode;
	time_t date;
	int dirtype;
	int outsize = 0;
	unsigned int numentries = 0;
	unsigned int maxentries = 0;
	BOOL finished = False;
	char *p;
	BOOL ok = False;
	int status_len;
	pstring path;
	char status[21];
	int dptr_num= -1;
	BOOL check_descend = False;
	BOOL expect_close = False;
	BOOL can_open = True;
	BOOL bad_path = False;
	NTSTATUS nt_status;
	START_PROFILE(SMBsearch);

	*mask = *directory = *fname = 0;

	/* If we were called as SMBffirst then we must expect close. */
	if(CVAL(inbuf,smb_com) == SMBffirst)
		expect_close = True;
  
	outsize = set_message(outbuf,1,3,True);
	maxentries = SVAL(inbuf,smb_vwv0); 
	dirtype = SVAL(inbuf,smb_vwv1);
	p = smb_buf(inbuf) + 1;
	p += srvstr_get_path(inbuf, path, p, sizeof(path), 0, STR_TERMINATE, &nt_status);
	if (!NT_STATUS_IS_OK(nt_status)) {
		END_PROFILE(SMBsearch);
		return ERROR_NT(nt_status);
	}
	p++;
	status_len = SVAL(p, 0);
	p += 2;
  
	/* dirtype &= ~aDIR; */

	if (status_len == 0) {
		SMB_STRUCT_STAT sbuf;
		pstring dir2;

		pstrcpy(directory,path);
		pstrcpy(dir2,path);
		unix_convert(directory,conn,0,&bad_path,&sbuf);
		unix_format(dir2);

		if (!check_name(directory,conn))
			can_open = False;

		p = strrchr_m(dir2,'/');
		if (p == NULL) {
			pstrcpy(mask,dir2);
			*dir2 = 0;
		} else {
			*p = 0;
			pstrcpy(mask,p+1);
		}

		p = strrchr_m(directory,'/');
		if (!p) 
			*directory = 0;
		else
			*p = 0;

		if (strlen(directory) == 0)
			pstrcpy(directory,".");
		memset((char *)status,'\0',21);
		SCVAL(status,0,(dirtype & 0x1F));
	} else {
		int status_dirtype;

		memcpy(status,p,21);
		status_dirtype = CVAL(status,0) & 0x1F;
		if (status_dirtype != (dirtype & 0x1F))
			dirtype = status_dirtype;

		conn->dirptr = dptr_fetch(status+12,&dptr_num);      
		if (!conn->dirptr)
			goto SearchEmpty;
		string_set(&conn->dirpath,dptr_path(dptr_num));
		pstrcpy(mask, dptr_wcard(dptr_num));
	}

	if (can_open) {
		p = smb_buf(outbuf) + 3;
		ok = True;
     
		if (status_len == 0) {
			dptr_num = dptr_create(conn,directory,True,expect_close,SVAL(inbuf,smb_pid));
			if (dptr_num < 0) {
				if(dptr_num == -2) {
					END_PROFILE(SMBsearch);
					return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnofids);
				}
				END_PROFILE(SMBsearch);
				return ERROR_DOS(ERRDOS,ERRnofids);
			}
			dptr_set_wcard(dptr_num, strdup(mask));
			dptr_set_attr(dptr_num, dirtype);
		} else {
			dirtype = dptr_attr(dptr_num);
		}

		DEBUG(4,("dptr_num is %d\n",dptr_num));

		if (ok) {
			if ((dirtype&0x1F) == aVOLID) {	  
				memcpy(p,status,21);
				make_dir_struct(p,"???????????",volume_label(SNUM(conn)),0,aVOLID,0);
				dptr_fill(p+12,dptr_num);
				if (dptr_zero(p+12) && (status_len==0))
					numentries = 1;
				else
					numentries = 0;
				p += DIR_STRUCT_SIZE;
			} else {
				unsigned int i;
				maxentries = MIN(maxentries, ((BUFFER_SIZE - (p - outbuf))/DIR_STRUCT_SIZE));

				DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
				conn->dirpath,lp_dontdescend(SNUM(conn))));
				if (in_list(conn->dirpath, lp_dontdescend(SNUM(conn)),True))
					check_descend = True;

				for (i=numentries;(i<maxentries) && !finished;i++) {
					finished = !get_dir_entry(conn,mask,dirtype,fname,&size,&mode,&date,check_descend);
					if (!finished) {
						memcpy(p,status,21);
						make_dir_struct(p,mask,fname,size,mode,date);
						dptr_fill(p+12,dptr_num);
						numentries++;
					}
					p += DIR_STRUCT_SIZE;
				}
			}
		} /* if (ok ) */
	}


  SearchEmpty:

	/* If we were called as SMBffirst with smb_search_id == NULL
		and no entries were found then return error and close dirptr 
		(X/Open spec) */

	if(ok && expect_close && numentries == 0 && status_len == 0) {
		if (Protocol < PROTOCOL_NT1) {
			SCVAL(outbuf,smb_rcls,ERRDOS);
			SSVAL(outbuf,smb_err,ERRnofiles);
		}
		/* Also close the dptr - we know it's gone */
		dptr_close(&dptr_num);
	} else if (numentries == 0 || !ok) {
		if (Protocol < PROTOCOL_NT1) {
			SCVAL(outbuf,smb_rcls,ERRDOS);
			SSVAL(outbuf,smb_err,ERRnofiles);
		}
		dptr_close(&dptr_num);
	}

	/* If we were called as SMBfunique, then we can close the dirptr now ! */
	if(dptr_num >= 0 && CVAL(inbuf,smb_com) == SMBfunique)
		dptr_close(&dptr_num);

	SSVAL(outbuf,smb_vwv0,numentries);
	SSVAL(outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
	SCVAL(smb_buf(outbuf),0,5);
	SSVAL(smb_buf(outbuf),1,numentries*DIR_STRUCT_SIZE);

	if (Protocol >= PROTOCOL_NT1)
		SSVAL(outbuf,smb_flg2,SVAL(outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
  
	outsize += DIR_STRUCT_SIZE*numentries;
	smb_setlen(outbuf,outsize - 4);
  
	if ((! *directory) && dptr_path(dptr_num))
		slprintf(directory, sizeof(directory)-1, "(%s)",dptr_path(dptr_num));

	DEBUG( 4, ( "%s mask=%s path=%s dtype=%d nument=%u of %u\n",
		smb_fn_name(CVAL(inbuf,smb_com)), 
		mask, directory, dirtype, numentries, maxentries ) );

	END_PROFILE(SMBsearch);
	return(outsize);
}

/****************************************************************************
 Reply to a fclose (stop directory search).
****************************************************************************/

int reply_fclose(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	int status_len;
	pstring path;
	char status[21];
	int dptr_num= -2;
	char *p;
	NTSTATUS err;

	START_PROFILE(SMBfclose);

	outsize = set_message(outbuf,1,0,True);
	p = smb_buf(inbuf) + 1;
	p += srvstr_get_path(inbuf, path, p, sizeof(path), 0, STR_TERMINATE, &err);
	if (!NT_STATUS_IS_OK(err)) {
		END_PROFILE(SMBfclose);
		return ERROR_NT(err);
	}
	p++;
	status_len = SVAL(p,0);
	p += 2;

	if (status_len == 0) {
		END_PROFILE(SMBfclose);
		return ERROR_DOS(ERRSRV,ERRsrverror);
	}

	memcpy(status,p,21);

	if(dptr_fetch(status+12,&dptr_num)) {
		/*  Close the dptr - we know it's gone */
		dptr_close(&dptr_num);
	}

	SSVAL(outbuf,smb_vwv0,0);

	DEBUG(3,("search close\n"));

	END_PROFILE(SMBfclose);
	return(outsize);
}

/****************************************************************************
 Reply to an open.
****************************************************************************/

int reply_open(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int outsize = 0;
	int fmode=0;
	int share_mode;
	SMB_OFF_T size = 0;
	time_t mtime=0;
	int rmode=0;
	SMB_STRUCT_STAT sbuf;
	BOOL bad_path = False;
	files_struct *fsp;
	int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
	uint16 dos_attr = SVAL(inbuf,smb_vwv1);
	NTSTATUS status;
	START_PROFILE(SMBopen);
 
	share_mode = SVAL(inbuf,smb_vwv0);

	srvstr_get_path(inbuf, fname, smb_buf(inbuf)+1, sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBopen);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);
    
	fsp = open_file_shared(conn,fname,&sbuf,share_mode,(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
			(uint32)dos_attr, oplock_request,&rmode,NULL);

	if (!fsp) {
		END_PROFILE(SMBopen);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnoaccess);
	}

	size = sbuf.st_size;
	fmode = dos_mode(conn,fname,&sbuf);
	mtime = sbuf.st_mtime;

	if (fmode & aDIR) {
		DEBUG(3,("attempt to open a directory %s\n",fname));
		close_file(fsp,False);
		END_PROFILE(SMBopen);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}
  
	outsize = set_message(outbuf,7,0,True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);
	SSVAL(outbuf,smb_vwv1,fmode);
	if(lp_dos_filetime_resolution(SNUM(conn)) )
		put_dos_date3(outbuf,smb_vwv2,mtime & ~1);
	else
		put_dos_date3(outbuf,smb_vwv2,mtime);
	SIVAL(outbuf,smb_vwv4,(uint32)size);
	SSVAL(outbuf,smb_vwv6,rmode);

	if (oplock_request && lp_fake_oplocks(SNUM(conn)))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
    
	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	END_PROFILE(SMBopen);
	return(outsize);
}

/****************************************************************************
 Reply to an open and X.
****************************************************************************/

int reply_open_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	pstring fname;
	int smb_mode = SVAL(inbuf,smb_vwv3);
	int smb_attr = SVAL(inbuf,smb_vwv5);
	/* Breakout the oplock request bits so we can set the
		reply bits separately. */
	BOOL ex_oplock_request = EXTENDED_OPLOCK_REQUEST(inbuf);
	BOOL core_oplock_request = CORE_OPLOCK_REQUEST(inbuf);
	BOOL oplock_request = ex_oplock_request | core_oplock_request;
#if 0
	int open_flags = SVAL(inbuf,smb_vwv2);
	int smb_sattr = SVAL(inbuf,smb_vwv4); 
	uint32 smb_time = make_unix_date3(inbuf+smb_vwv6);
#endif
	int smb_ofun = SVAL(inbuf,smb_vwv8);
	SMB_OFF_T size=0;
	int fmode=0,mtime=0,rmode=0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	BOOL bad_path = False;
	files_struct *fsp;
	NTSTATUS status;
	START_PROFILE(SMBopenX);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			END_PROFILE(SMBopenX);
			return reply_open_pipe_and_X(conn, inbuf,outbuf,length,bufsize);
		} else {
			END_PROFILE(SMBopenX);
			return ERROR_DOS(ERRSRV,ERRaccess);
		}
	}

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_get_path(inbuf, fname, smb_buf(inbuf), sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBopenX);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);
    
	fsp = open_file_shared(conn,fname,&sbuf,smb_mode,smb_ofun,(uint32)smb_attr,
			oplock_request, &rmode,&smb_action);
      
	if (!fsp) {
		END_PROFILE(SMBopenX);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnoaccess);
	}

	size = sbuf.st_size;
	fmode = dos_mode(conn,fname,&sbuf);
	mtime = sbuf.st_mtime;
	if (fmode & aDIR) {
		close_file(fsp,False);
		END_PROFILE(SMBopenX);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	/* If the caller set the extended oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for extended oplock reply.
	*/

	if (ex_oplock_request && lp_fake_oplocks(SNUM(conn)))
		smb_action |= EXTENDED_OPLOCK_GRANTED;

	if(ex_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		smb_action |= EXTENDED_OPLOCK_GRANTED;

	/* If the caller set the core oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for core oplock reply.
	*/

	if (core_oplock_request && lp_fake_oplocks(SNUM(conn)))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);

	if(core_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);

	set_message(outbuf,15,0,True);
	SSVAL(outbuf,smb_vwv2,fsp->fnum);
	SSVAL(outbuf,smb_vwv3,fmode);
	if(lp_dos_filetime_resolution(SNUM(conn)) )
		put_dos_date3(outbuf,smb_vwv4,mtime & ~1);
	else
		put_dos_date3(outbuf,smb_vwv4,mtime);
	SIVAL(outbuf,smb_vwv6,(uint32)size);
	SSVAL(outbuf,smb_vwv8,rmode);
	SSVAL(outbuf,smb_vwv11,smb_action);

	END_PROFILE(SMBopenX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a SMBulogoffX.
****************************************************************************/

int reply_ulogoffX(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	uint16 vuid = SVAL(inbuf,smb_uid);
	user_struct *vuser = get_valid_user_struct(vuid);
	START_PROFILE(SMBulogoffX);

	if(vuser == 0)
		DEBUG(3,("ulogoff, vuser id %d does not map to user.\n", vuid));

	/* in user level security we are supposed to close any files
		open by this user */
	if ((vuser != 0) && (lp_security() != SEC_SHARE))
		file_close_user(vuid);

	invalidate_vuid(vuid);

	set_message(outbuf,2,0,True);

	DEBUG( 3, ( "ulogoffX vuid=%d\n", vuid ) );

	END_PROFILE(SMBulogoffX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a mknew or a create.
****************************************************************************/

int reply_mknew(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int com;
	int outsize = 0;
	int createmode;
	int ofun = 0;
	BOOL bad_path = False;
	files_struct *fsp;
	int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;
	START_PROFILE(SMBcreate);
 
	com = SVAL(inbuf,smb_com);

	createmode = SVAL(inbuf,smb_vwv0);
	srvstr_get_path(inbuf, fname, smb_buf(inbuf) + 1, sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcreate);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);

	if (createmode & aVOLID)
		DEBUG(0,("Attempt to create file (%s) with volid set - please report this\n",fname));
  
	if(com == SMBmknew) {
		/* We should fail if file exists. */
		ofun = FILE_CREATE_IF_NOT_EXIST;
	} else {
		/* SMBcreate - Create if file doesn't exist, truncate if it does. */
		ofun = FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE;
	}

	/* Open file in dos compatibility share mode. */
	fsp = open_file_shared(conn,fname,&sbuf,SET_DENY_MODE(DENY_FCB)|SET_OPEN_MODE(DOS_OPEN_FCB), 
			ofun, (uint32)createmode, oplock_request, NULL, NULL);
  
	if (!fsp) {
		END_PROFILE(SMBcreate);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnoaccess);
	}
 
	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);

	if (oplock_request && lp_fake_oplocks(SNUM(conn)))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
 
	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
 
	DEBUG( 2, ( "new file %s\n", fname ) );
	DEBUG( 3, ( "mknew %s fd=%d dmode=%d\n", fname, fsp->fd, createmode ) );

	END_PROFILE(SMBcreate);
	return(outsize);
}

/****************************************************************************
 Reply to a create temporary file.
****************************************************************************/

int reply_ctemp(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int outsize = 0;
	int createattr;
	BOOL bad_path = False;
	files_struct *fsp;
	int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
	int tmpfd;
	SMB_STRUCT_STAT sbuf;
	char *p, *s;
	NTSTATUS status;
	unsigned int namelen;

	START_PROFILE(SMBctemp);

	createattr = SVAL(inbuf,smb_vwv0);
	srvstr_get_path(inbuf, fname, smb_buf(inbuf)+1, sizeof(fname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBctemp);
		return ERROR_NT(status);
	}
	if (*fname) {
		pstrcat(fname,"/TMXXXXXX");
	} else {
		pstrcat(fname,"TMXXXXXX");
	}

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);
  
	tmpfd = smb_mkstemp(fname);
	if (tmpfd == -1) {
		END_PROFILE(SMBctemp);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	SMB_VFS_STAT(conn,fname,&sbuf);

	/* Open file in dos compatibility share mode. */
	/* We should fail if file does not exist. */
	fsp = open_file_shared(conn,fname,&sbuf,
		SET_DENY_MODE(DENY_FCB)|SET_OPEN_MODE(DOS_OPEN_FCB),
		FILE_EXISTS_OPEN|FILE_FAIL_IF_NOT_EXIST,
		(uint32)createattr, oplock_request, NULL, NULL);

	/* close fd from smb_mkstemp() */
	close(tmpfd);

	if (!fsp) {
		END_PROFILE(SMBctemp);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);

	/* the returned filename is relative to the directory */
	s = strrchr_m(fname, '/');
	if (!s)
		s = fname;
	else
		s++;

	p = smb_buf(outbuf);
#if 0
	/* Tested vs W2K3 - this doesn't seem to be here - null terminated filename is the only
	   thing in the byte section. JRA */
	SSVALS(p, 0, -1); /* what is this? not in spec */
#endif
	namelen = srvstr_push(outbuf, p, s, -1, STR_ASCII|STR_TERMINATE);
	p += namelen;
	outsize = set_message_end(outbuf, p);

	if (oplock_request && lp_fake_oplocks(SNUM(conn)))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  
	if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);

	DEBUG( 2, ( "created temp file %s\n", fname ) );
	DEBUG( 3, ( "ctemp %s fd=%d umode=%o\n",
			fname, fsp->fd, sbuf.st_mode ) );

	END_PROFILE(SMBctemp);
	return(outsize);
}

/*******************************************************************
 Check if a user is allowed to rename a file.
********************************************************************/

static NTSTATUS can_rename(char *fname,connection_struct *conn, SMB_STRUCT_STAT *pst)
{
	int smb_action;
	int access_mode;
	files_struct *fsp;

	if (!CAN_WRITE(conn))
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	
	if (S_ISDIR(pst->st_mode))
		return NT_STATUS_OK;

	/* We need a better way to return NT status codes from open... */
	unix_ERR_class = 0;
	unix_ERR_code = 0;

	fsp = open_file_shared1(conn, fname, pst, DELETE_ACCESS, SET_DENY_MODE(DENY_ALL),
		(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), FILE_ATTRIBUTE_NORMAL, 0, &access_mode, &smb_action);

	if (!fsp) {
		NTSTATUS ret = NT_STATUS_ACCESS_DENIED;
		if (unix_ERR_class == ERRDOS && unix_ERR_code == ERRbadshare)
			ret = NT_STATUS_SHARING_VIOLATION;
		unix_ERR_class = 0;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
		return ret;
	}
	close_file(fsp,False);
	return NT_STATUS_OK;
}

/*******************************************************************
 Check if a user is allowed to delete a file.
********************************************************************/

static NTSTATUS can_delete(char *fname,connection_struct *conn, int dirtype, BOOL bad_path)
{
	SMB_STRUCT_STAT sbuf;
	int fmode;
	int smb_action;
	int access_mode;
	files_struct *fsp;

	DEBUG(10,("can_delete: %s, dirtype = %d\n",
		fname, dirtype ));

	if (!CAN_WRITE(conn))
		return NT_STATUS_MEDIA_WRITE_PROTECTED;

	if (SMB_VFS_LSTAT(conn,fname,&sbuf) != 0) {
	        if(errno == ENOENT) {
			if (bad_path)
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			else
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		return map_nt_error_from_unix(errno);
	}

	fmode = dos_mode(conn,fname,&sbuf);

	/* Can't delete a directory. */
	if (fmode & aDIR)
		return NT_STATUS_FILE_IS_A_DIRECTORY;
#if 0 /* JRATEST */
	else if (dirtype & aDIR) /* Asked for a directory and it isn't. */
		return NT_STATUS_OBJECT_NAME_INVALID;
#endif /* JRATEST */

	if (!lp_delete_readonly(SNUM(conn))) {
		if (fmode & aRONLY)
			return NT_STATUS_CANNOT_DELETE;
	}
	if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM))
		return NT_STATUS_NO_SUCH_FILE;

	/* We need a better way to return NT status codes from open... */
	unix_ERR_class = 0;
	unix_ERR_code = 0;

	fsp = open_file_shared1(conn, fname, &sbuf, DELETE_ACCESS, SET_DENY_MODE(DENY_ALL),
		(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), FILE_ATTRIBUTE_NORMAL, 0, &access_mode, &smb_action);

	if (!fsp) {
		NTSTATUS ret = NT_STATUS_ACCESS_DENIED;
		if (!NT_STATUS_IS_OK(unix_ERR_ntstatus))
			ret = unix_ERR_ntstatus;
		else if (unix_ERR_class == ERRDOS && unix_ERR_code == ERRbadshare)
			ret = NT_STATUS_SHARING_VIOLATION;
		unix_ERR_class = 0;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
		return ret;
	}
	close_file(fsp,False);
	return NT_STATUS_OK;
}

/****************************************************************************
 The guts of the unlink command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS unlink_internals(connection_struct *conn, int dirtype, char *name)
{
	pstring directory;
	pstring mask;
	char *p;
	int count=0;
	NTSTATUS error = NT_STATUS_OK;
	BOOL has_wild;
	BOOL bad_path = False;
	BOOL rc = True;
	SMB_STRUCT_STAT sbuf;
	
	*directory = *mask = 0;
	
	/* We must check for wildcards in the name given
	 * directly by the client - before any unmangling.
	 * This prevents an unmangling of a UNIX name containing
	 * a DOS wildcard like '*' or '?' from unmangling into
	 * a wildcard delete which was not intended.
	 * FIX for #226. JRA.
	 */

	has_wild = ms_has_wild(name);

	rc = unix_convert(name,conn,0,&bad_path,&sbuf);
	
	p = strrchr_m(name,'/');
	if (!p) {
		pstrcpy(directory,".");
		pstrcpy(mask,name);
	} else {
		*p = 0;
		pstrcpy(directory,name);
		pstrcpy(mask,p+1);
	}
	
	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */
	
	if (!rc && mangle_is_mangled(mask))
		mangle_check_cache( mask );
	
	if (!has_wild) {
		pstrcat(directory,"/");
		pstrcat(directory,mask);
		error = can_delete(directory,conn,dirtype,bad_path);
		if (!NT_STATUS_IS_OK(error))
			return error;

		if (SMB_VFS_UNLINK(conn,directory) == 0) {
			count++;
		}
	} else {
		void *dirptr = NULL;
		const char *dname;
		
		if (check_name(directory,conn))
			dirptr = OpenDir(conn, directory, True);
		
		/* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
		   the pattern matches against the long name, otherwise the short name 
		   We don't implement this yet XXXX
		*/
		
		if (dirptr) {
			error = NT_STATUS_NO_SUCH_FILE;
			
			if (strequal(mask,"????????.???"))
				pstrcpy(mask,"*");

			while ((dname = ReadDirName(dirptr))) {
				pstring fname;
				BOOL sys_direntry = False;
				pstrcpy(fname,dname);

				/* Quick check for "." and ".." */
				if (fname[0] == '.') {
					if (!fname[1] || (fname[1] == '.' && !fname[2])) {
						if ((dirtype & aDIR)) {
							sys_direntry = True;
						} else {
							continue;
						}
					}
				}

				if(!mask_match(fname, mask, case_sensitive))
					continue;
				
				if (sys_direntry) {
					error = NT_STATUS_OBJECT_NAME_INVALID;
					break;
				}

				slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
				error = can_delete(fname,conn,dirtype,bad_path);
				if (!NT_STATUS_IS_OK(error)) {
					continue;
				}
				if (SMB_VFS_UNLINK(conn,fname) == 0)
					count++;
				DEBUG(3,("unlink_internals: succesful unlink [%s]\n",fname));
			}
			CloseDir(dirptr);
		}
	}
	
	if (count == 0 && NT_STATUS_IS_OK(error)) {
		error = map_nt_error_from_unix(errno);
	}

	return error;
}

/****************************************************************************
 Reply to a unlink
****************************************************************************/

int reply_unlink(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, 
		 int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	int dirtype;
	NTSTATUS status;
	START_PROFILE(SMBunlink);
	
	dirtype = SVAL(inbuf,smb_vwv0);
	
	srvstr_get_path(inbuf, name, smb_buf(inbuf) + 1, sizeof(name), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBunlink);
		return ERROR_NT(status);
	}
	
	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);
	
	DEBUG(3,("reply_unlink : %s\n",name));
	
	status = unlink_internals(conn, dirtype, name);
	if (!NT_STATUS_IS_OK(status))
		return ERROR_NT(status);

	/*
	 * Win2k needs a changenotify request response before it will
	 * update after a rename..
	 */
	process_pending_change_notify_queue((time_t)0);
	
	outsize = set_message(outbuf,0,0,True);
  
	END_PROFILE(SMBunlink);
	return outsize;
}

/****************************************************************************
 Fail for readbraw.
****************************************************************************/

void fail_readraw(void)
{
	pstring errstr;
	slprintf(errstr, sizeof(errstr)-1, "FAIL ! reply_readbraw: socket write fail (%s)",
		strerror(errno) );
	exit_server(errstr);
}

/****************************************************************************
 Use sendfile in readbraw.
****************************************************************************/

void send_file_readbraw(connection_struct *conn, files_struct *fsp, SMB_OFF_T startpos, size_t nread,
		ssize_t mincount, char *outbuf)
{
	ssize_t ret=0;

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet and on a file
	 * that is exclusively oplocked. reply_readbraw has already checked the length.
	 */

	if ((nread > 0) && (lp_write_cache_size(SNUM(conn)) == 0) &&
			EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type) && lp_use_sendfile(SNUM(conn)) ) {
		DATA_BLOB header;

		_smb_setlen(outbuf,nread);
		header.data = outbuf;
		header.length = 4;
		header.free = NULL;

		if ( SMB_VFS_SENDFILE( smbd_server_fd(), fsp, fsp->fd, &header, startpos, nread) == -1) {
			/*
			 * Special hack for broken Linux with no 64 bit clean sendfile. If we
			 * return ENOSYS then pretend we just got a normal read.
			 */
			if (errno == ENOSYS)
				goto normal_read;

			DEBUG(0,("send_file_readbraw: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server("send_file_readbraw sendfile failed");
		}

	}

  normal_read:
#endif

	if (nread > 0) {
		ret = read_file(fsp,outbuf+4,startpos,nread);
#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
		if (ret < mincount)
			ret = 0;
#else
		if (ret < nread)
			ret = 0;
#endif
	}

	_smb_setlen(outbuf,ret);
	if (write_data(smbd_server_fd(),outbuf,4+ret) != 4+ret)
		fail_readraw();
}

/****************************************************************************
 Reply to a readbraw (core+ protocol).
****************************************************************************/

int reply_readbraw(connection_struct *conn, char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	extern struct current_user current_user;
	ssize_t maxcount,mincount;
	size_t nread = 0;
	SMB_OFF_T startpos;
	char *header = outbuf;
	files_struct *fsp;
	START_PROFILE(SMBreadbraw);

	if (srv_is_signing_active()) {
		exit_server("reply_readbraw: SMB signing is active - raw reads/writes are disallowed.");
	}

	/*
	 * Special check if an oplock break has been issued
	 * and the readraw request croses on the wire, we must
	 * return a zero length response here.
	 */

	if(global_oplock_break) {
		_smb_setlen(header,0);
		if (write_data(smbd_server_fd(),header,4) != 4)
			fail_readraw();
		DEBUG(5,("readbraw - oplock break finished\n"));
		END_PROFILE(SMBreadbraw);
		return -1;
	}

	fsp = file_fsp(inbuf,smb_vwv0);

	if (!FNUM_OK(fsp,conn) || !fsp->can_read) {
		/*
		 * fsp could be NULL here so use the value from the packet. JRA.
		 */
		DEBUG(3,("fnum %d not open in readbraw - cache prime?\n",(int)SVAL(inbuf,smb_vwv0)));
		_smb_setlen(header,0);
		if (write_data(smbd_server_fd(),header,4) != 4)
			fail_readraw();
		END_PROFILE(SMBreadbraw);
		return(-1);
	}

	CHECK_FSP(fsp,conn);

	flush_write_cache(fsp, READRAW_FLUSH);

	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
	if(CVAL(inbuf,smb_wct) == 10) {
		/*
		 * This is a large offset (64 bit) read.
		 */
#ifdef LARGE_SMB_OFF_T

		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv8)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv8) != 0) {
			DEBUG(0,("readbraw - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv8) ));
			_smb_setlen(header,0);
			if (write_data(smbd_server_fd(),header,4) != 4)
				fail_readraw();
			END_PROFILE(SMBreadbraw);
			return(-1);
		}

#endif /* LARGE_SMB_OFF_T */

		if(startpos < 0) {
			DEBUG(0,("readbraw - negative 64 bit readraw offset (%.0f) !\n", (double)startpos ));
			_smb_setlen(header,0);
			if (write_data(smbd_server_fd(),header,4) != 4)
				fail_readraw();
			END_PROFILE(SMBreadbraw);
			return(-1);
		}      
	}
	maxcount = (SVAL(inbuf,smb_vwv3) & 0xFFFF);
	mincount = (SVAL(inbuf,smb_vwv4) & 0xFFFF);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535,maxcount);

	if (!is_locked(fsp,conn,(SMB_BIG_UINT)maxcount,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		SMB_OFF_T size = fsp->size;
		SMB_OFF_T sizeneeded = startpos + maxcount;
  
		if (size < sizeneeded) {
			SMB_STRUCT_STAT st;
			if (SMB_VFS_FSTAT(fsp,fsp->fd,&st) == 0)
				size = st.st_size;
			if (!fsp->can_write) 
				fsp->size = size;
		}

		if (startpos >= size)
			nread = 0;
		else
			nread = MIN(maxcount,(size - startpos));	  
	}

#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
	if (nread < mincount)
		nread = 0;
#endif
  
	DEBUG( 3, ( "readbraw fnum=%d start=%.0f max=%d min=%d nread=%d\n", fsp->fnum, (double)startpos,
				(int)maxcount, (int)mincount, (int)nread ) );
  
	send_file_readbraw(conn, fsp, startpos, nread, mincount, outbuf);

	DEBUG(5,("readbraw finished\n"));
	END_PROFILE(SMBreadbraw);
	return -1;
}

/****************************************************************************
 Reply to a lockread (core+ protocol).
****************************************************************************/

int reply_lockread(connection_struct *conn, char *inbuf,char *outbuf, int length, int dum_buffsiz)
{
	ssize_t nread = -1;
	char *data;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t numtoread;
	NTSTATUS status;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	BOOL my_lock_ctx = False;
	START_PROFILE(SMBlockread);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	release_level_2_oplocks_on_change(fsp);

	numtoread = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  
	outsize = set_message(outbuf,5,3,True);
	numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
	data = smb_buf(outbuf) + 3;
	
	/*
	 * NB. Discovered by Menny Hamburger at Mainsoft. This is a core+
	 * protocol request that predates the read/write lock concept. 
	 * Thus instead of asking for a read lock here we need to ask
	 * for a write lock. JRA.
	 * Note that the requested lock size is unaffected by max_recv.
	 */
	
	status = do_lock_spin(fsp, conn, SVAL(inbuf,smb_pid), 
			 (SMB_BIG_UINT)numtoread, (SMB_BIG_UINT)startpos, WRITE_LOCK, &my_lock_ctx);

	if (NT_STATUS_V(status)) {
#if 0
		/*
		 * We used to make lockread a blocking lock. It turns out
		 * that this isn't on W2k. Found by the Samba 4 RAW-READ torture
		 * tester. JRA.
		 */

		if (lp_blocking_locks(SNUM(conn)) && !my_lock_ctx && ERROR_WAS_LOCK_DENIED(status)) {
			/*
			 * A blocking lock was requested. Package up
			 * this smb into a queued request and push it
			 * onto the blocking lock queue.
			 */
			if(push_blocking_lock_request(inbuf, length, -1, 0, SVAL(inbuf,smb_pid), (SMB_BIG_UINT)startpos,
								(SMB_BIG_UINT)numtoread)) {
				END_PROFILE(SMBlockread);
				return -1;
			}
		}
#endif
		END_PROFILE(SMBlockread);
		return ERROR_NT(status);
	}

	/*
	 * However the requested READ size IS affected by max_recv. Insanity.... JRA.
	 */

	if (numtoread > max_recv) {
		DEBUG(0,("reply_lockread: requested read size (%u) is greater than maximum allowed (%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)max_recv ));
		numtoread = MIN(numtoread,max_recv);
	}
	nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		END_PROFILE(SMBlockread);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}
	
	outsize += nread;
	SSVAL(outbuf,smb_vwv0,nread);
	SSVAL(outbuf,smb_vwv5,nread+3);
	SSVAL(smb_buf(outbuf),1,nread);
	
	DEBUG(3,("lockread fnum=%d num=%d nread=%d\n",
		 fsp->fnum, (int)numtoread, (int)nread));

	END_PROFILE(SMBlockread);
	return(outsize);
}

/****************************************************************************
 Reply to a read.
****************************************************************************/

int reply_read(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtoread;
	ssize_t nread = 0;
	char *data;
	SMB_OFF_T startpos;
	int outsize = 0;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBread);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	numtoread = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);

	outsize = set_message(outbuf,5,3,True);
	numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
	/*
	 * The requested read size cannot be greater than max_recv. JRA.
	 */
	if (numtoread > max_recv) {
		DEBUG(0,("reply_read: requested read size (%u) is greater than maximum allowed (%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)max_recv ));
		numtoread = MIN(numtoread,max_recv);
	}

	data = smb_buf(outbuf) + 3;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtoread,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		END_PROFILE(SMBread);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	if (numtoread > 0)
		nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		END_PROFILE(SMBread);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}
  
	outsize += nread;
	SSVAL(outbuf,smb_vwv0,nread);
	SSVAL(outbuf,smb_vwv5,nread+3);
	SCVAL(smb_buf(outbuf),0,1);
	SSVAL(smb_buf(outbuf),1,nread);
  
	DEBUG( 3, ( "read fnum=%d num=%d nread=%d\n",
		fsp->fnum, (int)numtoread, (int)nread ) );

	END_PROFILE(SMBread);
	return(outsize);
}

/****************************************************************************
 Reply to a read and X - possibly using sendfile.
****************************************************************************/

int send_file_readX(connection_struct *conn, char *inbuf,char *outbuf,int length, 
		files_struct *fsp, SMB_OFF_T startpos, size_t smb_maxcnt)
{
	ssize_t nread = -1;
	char *data = smb_buf(outbuf);

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet and on a file
	 * that is exclusively oplocked.
	 */

	if ((CVAL(inbuf,smb_vwv0) == 0xFF) && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type) &&
			lp_use_sendfile(SNUM(conn)) && (lp_write_cache_size(SNUM(conn)) == 0) ) {
		SMB_STRUCT_STAT sbuf;
		DATA_BLOB header;

		if(SMB_VFS_FSTAT(fsp,fsp->fd, &sbuf) == -1)
			return(UNIXERROR(ERRDOS,ERRnoaccess));

		if (startpos > sbuf.st_size)
			goto normal_read;

		if (smb_maxcnt > (sbuf.st_size - startpos))
			smb_maxcnt = (sbuf.st_size - startpos);

		if (smb_maxcnt == 0)
			goto normal_read;

		/* 
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
		SSVAL(outbuf,smb_vwv5,smb_maxcnt);
		SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
		SSVAL(smb_buf(outbuf),-2,smb_maxcnt);
		SCVAL(outbuf,smb_vwv0,0xFF);
		set_message(outbuf,12,smb_maxcnt,False);
		header.data = outbuf;
		header.length = data - outbuf;
		header.free = NULL;

		if ( SMB_VFS_SENDFILE( smbd_server_fd(), fsp, fsp->fd, &header, startpos, smb_maxcnt) == -1) {
			/*
			 * Special hack for broken Linux with no 64 bit clean sendfile. If we
			 * return ENOSYS then pretend we just got a normal read.
			 */
			if (errno == ENOSYS)
				goto normal_read;

			DEBUG(0,("send_file_readX: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server("send_file_readX sendfile failed");
		}

		DEBUG( 3, ( "send_file_readX: sendfile fnum=%d max=%d nread=%d\n",
			fsp->fnum, (int)smb_maxcnt, (int)nread ) );
		return -1;
	}

  normal_read:

#endif

	nread = read_file(fsp,data,startpos,smb_maxcnt);
  
	if (nread < 0) {
		END_PROFILE(SMBreadX);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
	SSVAL(outbuf,smb_vwv5,nread);
	SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
	SSVAL(smb_buf(outbuf),-2,nread);
  
	DEBUG( 3, ( "send_file_readX fnum=%d max=%d nread=%d\n",
		fsp->fnum, (int)smb_maxcnt, (int)nread ) );

	return nread;
}

/****************************************************************************
 Reply to a read and X.
****************************************************************************/

int reply_read_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	files_struct *fsp = file_fsp(inbuf,smb_vwv2);
	SMB_OFF_T startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	ssize_t nread = -1;
	size_t smb_maxcnt = SVAL(inbuf,smb_vwv5);
#if 0
	size_t smb_mincnt = SVAL(inbuf,smb_vwv6);
#endif

	START_PROFILE(SMBreadX);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBreadX);
		return reply_pipe_read_and_X(inbuf,outbuf,length,bufsize);
	}

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	set_message(outbuf,12,0,True);

	if(CVAL(inbuf,smb_wct) == 12) {
#ifdef LARGE_SMB_OFF_T
		/*
		 * This is a large offset (64 bit) read.
		 */
		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv10)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv10) != 0) {
			DEBUG(0,("reply_read_and_X - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv10) ));
			END_PROFILE(SMBreadX);
			return ERROR_DOS(ERRDOS,ERRbadaccess);
		}

#endif /* LARGE_SMB_OFF_T */

	}

	if (is_locked(fsp,conn,(SMB_BIG_UINT)smb_maxcnt,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		END_PROFILE(SMBreadX);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	nread = send_file_readX(conn, inbuf, outbuf, length, fsp, startpos, smb_maxcnt);
	if (nread != -1)
		nread = chain_reply(inbuf,outbuf,length,bufsize);

	END_PROFILE(SMBreadX);
	return nread;
}

/****************************************************************************
 Reply to a writebraw (core+ or LANMAN1.0 protocol).
****************************************************************************/

int reply_writebraw(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	ssize_t nwritten=0;
	ssize_t total_written=0;
	size_t numtowrite=0;
	size_t tcount;
	SMB_OFF_T startpos;
	char *data=NULL;
	BOOL write_through;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int outsize = 0;
	START_PROFILE(SMBwritebraw);

	if (srv_is_signing_active()) {
		exit_server("reply_writebraw: SMB signing is active - raw reads/writes are disallowed.");
	}

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);
  
	tcount = IVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	write_through = BITSETW(inbuf+smb_vwv7,0);

	/* We have to deal with slightly different formats depending
		on whether we are using the core+ or lanman1.0 protocol */

	if(Protocol <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf(inbuf),-2);
		data = smb_buf(inbuf);
	} else {
		numtowrite = SVAL(inbuf,smb_vwv10);
		data = smb_base(inbuf) + SVAL(inbuf, smb_vwv11);
	}

	/* force the error type */
	SCVAL(inbuf,smb_com,SMBwritec);
	SCVAL(outbuf,smb_com,SMBwritec);

	if (is_locked(fsp,conn,(SMB_BIG_UINT)tcount,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwritebraw);
		return(ERROR_DOS(ERRDOS,ERRlock));
	}

	if (numtowrite>0)
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	DEBUG(3,("writebraw1 fnum=%d start=%.0f num=%d wrote=%d sync=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite, (int)nwritten, (int)write_through));

	if (nwritten < (ssize_t)numtowrite)  {
		END_PROFILE(SMBwritebraw);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	total_written = nwritten;

	/* Return a message to the redirector to tell it to send more bytes */
	SCVAL(outbuf,smb_com,SMBwritebraw);
	SSVALS(outbuf,smb_vwv0,-1);
	outsize = set_message(outbuf,Protocol>PROTOCOL_COREPLUS?1:0,0,True);
	if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("reply_writebraw: send_smb failed.");
  
	/* Now read the raw data into the buffer and write it */
	if (read_smb_length(smbd_server_fd(),inbuf,SMB_SECONDARY_WAIT) == -1) {
		exit_server("secondary writebraw failed");
	}
  
	/* Even though this is not an smb message, smb_len returns the generic length of an smb message */
	numtowrite = smb_len(inbuf);

	/* Set up outbuf to return the correct return */
	outsize = set_message(outbuf,1,0,True);
	SCVAL(outbuf,smb_com,SMBwritec);
	SSVAL(outbuf,smb_vwv0,total_written);

	if (numtowrite != 0) {

		if (numtowrite > BUFFER_SIZE) {
			DEBUG(0,("reply_writebraw: Oversize secondary write raw requested (%u). Terminating\n",
				(unsigned int)numtowrite ));
			exit_server("secondary writebraw failed");
		}

		if (tcount > nwritten+numtowrite) {
			DEBUG(3,("Client overestimated the write %d %d %d\n",
				(int)tcount,(int)nwritten,(int)numtowrite));
		}

		if (read_data( smbd_server_fd(), inbuf+4, numtowrite) != numtowrite ) {
			DEBUG(0,("reply_writebraw: Oversize secondary write raw read failed (%s). Terminating\n",
				strerror(errno) ));
			exit_server("secondary writebraw failed");
		}

		nwritten = write_file(fsp,inbuf+4,startpos+nwritten,numtowrite);

		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);      
		}

		if (nwritten > 0)
			total_written += nwritten;
 	}
 
	if ((lp_syncalways(SNUM(conn)) || write_through) && lp_strict_sync(SNUM(conn)))
		sync_file(conn,fsp);

	DEBUG(3,("writebraw2 fnum=%d start=%.0f num=%d wrote=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite,(int)total_written));

	/* we won't return a status if write through is not selected - this follows what WfWg does */
	END_PROFILE(SMBwritebraw);
	if (!write_through && total_written==tcount) {

#if RABBIT_PELLET_FIX
		/*
		 * Fix for "rabbit pellet" mode, trigger an early TCP ack by
		 * sending a SMBkeepalive. Thanks to DaveCB at Sun for this. JRA.
		 */
		if (!send_keepalive(smbd_server_fd()))
			exit_server("reply_writebraw: send of keepalive failed");
#endif
		return(-1);
	}

	return(outsize);
}

/****************************************************************************
 Reply to a writeunlock (core+).
****************************************************************************/

int reply_writeunlock(connection_struct *conn, char *inbuf,char *outbuf, 
		      int size, int dum_buffsize)
{
	ssize_t nwritten = -1;
	size_t numtowrite;
	SMB_OFF_T startpos;
	char *data;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int outsize = 0;
	START_PROFILE(SMBwriteunlock);
	
	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	data = smb_buf(inbuf) + 3;
  
	if (numtowrite && is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, 
		      WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteunlock);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	/* The special X/Open SMB protocol handling of
	   zero length writes is *NOT* done for
	   this call */
	if(numtowrite == 0)
		nwritten = 0;
	else
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	if (lp_syncalways(SNUM(conn)))
		sync_file(conn,fsp);

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwriteunlock);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	if (numtowrite) {
		status = do_unlock(fsp, conn, SVAL(inbuf,smb_pid), (SMB_BIG_UINT)numtowrite, 
				   (SMB_BIG_UINT)startpos);
		if (NT_STATUS_V(status)) {
			END_PROFILE(SMBwriteunlock);
			return ERROR_NT(status);
		}
	}
	
	outsize = set_message(outbuf,1,0,True);
	
	SSVAL(outbuf,smb_vwv0,nwritten);
	
	DEBUG(3,("writeunlock fnum=%d num=%d wrote=%d\n",
		 fsp->fnum, (int)numtowrite, (int)nwritten));
	
	END_PROFILE(SMBwriteunlock);
	return outsize;
}

/****************************************************************************
 Reply to a write.
****************************************************************************/

int reply_write(connection_struct *conn, char *inbuf,char *outbuf,int size,int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	SMB_OFF_T startpos;
	char *data;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int outsize = 0;
	START_PROFILE(SMBwrite);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBwrite);
		return reply_pipe_write(inbuf,outbuf,size,dum_buffsize);
	}

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	data = smb_buf(inbuf) + 3;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwrite);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	/*
	 * X/Open SMB protocol says that if smb_vwv1 is
	 * zero then the file size should be extended or
	 * truncated to the size given in smb_vwv[2-3].
	 */

	if(numtowrite == 0) {
		/*
		 * This is actually an allocate call, and set EOF. JRA.
		 */
		nwritten = vfs_allocate_file_space(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			END_PROFILE(SMBwrite);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
		nwritten = vfs_set_filelen(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			END_PROFILE(SMBwrite);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
	} else
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	if (lp_syncalways(SNUM(conn)))
		sync_file(conn,fsp);

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwrite);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	outsize = set_message(outbuf,1,0,True);
  
	SSVAL(outbuf,smb_vwv0,nwritten);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(outbuf,smb_rcls,ERRHRD);
		SSVAL(outbuf,smb_err,ERRdiskfull);      
	}
  
	DEBUG(3,("write fnum=%d num=%d wrote=%d\n", fsp->fnum, (int)numtowrite, (int)nwritten));

	END_PROFILE(SMBwrite);
	return(outsize);
}

/****************************************************************************
 Reply to a write and X.
****************************************************************************/

int reply_write_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	files_struct *fsp = file_fsp(inbuf,smb_vwv2);
	SMB_OFF_T startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	size_t numtowrite = SVAL(inbuf,smb_vwv10);
	BOOL write_through = BITSETW(inbuf+smb_vwv7,0);
	ssize_t nwritten = -1;
	unsigned int smb_doff = SVAL(inbuf,smb_vwv11);
	unsigned int smblen = smb_len(inbuf);
	char *data;
	BOOL large_writeX = ((CVAL(inbuf,smb_wct) == 14) && (smblen > 0xFFFF));
	START_PROFILE(SMBwriteX);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBwriteX);
		return reply_pipe_write_and_X(inbuf,outbuf,length,bufsize);
	}

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	/* Deal with possible LARGE_WRITEX */
	if (large_writeX)
		numtowrite |= ((((size_t)SVAL(inbuf,smb_vwv9)) & 1 )<<16);

	if(smb_doff > smblen || (smb_doff + numtowrite > smblen)) {
		END_PROFILE(SMBwriteX);
		return ERROR_DOS(ERRDOS,ERRbadmem);
	}

	data = smb_base(inbuf) + smb_doff;

	if(CVAL(inbuf,smb_wct) == 14) {
#ifdef LARGE_SMB_OFF_T
		/*
		 * This is a large offset (64 bit) write.
		 */
		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv12)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv12) != 0) {
			DEBUG(0,("reply_write_and_X - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv12) ));
			END_PROFILE(SMBwriteX);
			return ERROR_DOS(ERRDOS,ERRbadaccess);
		}

#endif /* LARGE_SMB_OFF_T */
	}

	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteX);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	/* X/Open SMB protocol says that, unlike SMBwrite
	if the length is zero then NO truncation is
	done, just a write of zero. To truncate a file,
	use SMBwrite. */

	if(numtowrite == 0)
		nwritten = 0;
	else
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwriteX);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	set_message(outbuf,6,0,True);
  
	SSVAL(outbuf,smb_vwv2,nwritten);
	if (large_writeX)
		SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(outbuf,smb_rcls,ERRHRD);
		SSVAL(outbuf,smb_err,ERRdiskfull);      
	}

	DEBUG(3,("writeX fnum=%d num=%d wrote=%d\n",
		fsp->fnum, (int)numtowrite, (int)nwritten));

	if (lp_syncalways(SNUM(conn)) || write_through)
		sync_file(conn,fsp);

	END_PROFILE(SMBwriteX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a lseek.
****************************************************************************/

int reply_lseek(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	SMB_OFF_T startpos;
	SMB_OFF_T res= -1;
	int mode,umode;
	int outsize = 0;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBlseek);

	CHECK_FSP(fsp,conn);

	flush_write_cache(fsp, SEEK_FLUSH);

	mode = SVAL(inbuf,smb_vwv1) & 3;
	/* NB. This doesn't use IVAL_TO_SMB_OFF_T as startpos can be signed in this case. */
	startpos = (SMB_OFF_T)IVALS(inbuf,smb_vwv2);

	switch (mode) {
		case 0:
			umode = SEEK_SET;
			res = startpos;
			break;
		case 1:
			umode = SEEK_CUR;
			res = fsp->pos + startpos;
			break;
		case 2:
			umode = SEEK_END;
			break;
		default:
			umode = SEEK_SET;
			res = startpos;
			break;
	}

	if (umode == SEEK_END) {
		if((res = SMB_VFS_LSEEK(fsp,fsp->fd,startpos,umode)) == -1) {
			if(errno == EINVAL) {
				SMB_OFF_T current_pos = startpos;
				SMB_STRUCT_STAT sbuf;

				if(SMB_VFS_FSTAT(fsp,fsp->fd, &sbuf) == -1) {
					END_PROFILE(SMBlseek);
					return(UNIXERROR(ERRDOS,ERRnoaccess));
				}

				current_pos += sbuf.st_size;
				if(current_pos < 0)
					res = SMB_VFS_LSEEK(fsp,fsp->fd,0,SEEK_SET);
			}
		}

		if(res == -1) {
			END_PROFILE(SMBlseek);
			return(UNIXERROR(ERRDOS,ERRnoaccess));
		}
	}

	fsp->pos = res;
  
	outsize = set_message(outbuf,2,0,True);
	SIVAL(outbuf,smb_vwv0,res);
  
	DEBUG(3,("lseek fnum=%d ofs=%.0f newpos = %.0f mode=%d\n",
		fsp->fnum, (double)startpos, (double)res, mode));

	END_PROFILE(SMBlseek);
	return(outsize);
}

/****************************************************************************
 Reply to a flush.
****************************************************************************/

int reply_flush(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	uint16 fnum = SVAL(inbuf,smb_vwv0);
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBflush);

	if (fnum != 0xFFFF)
		CHECK_FSP(fsp,conn);
	
	if (!fsp) {
		file_sync_all(conn);
	} else {
		sync_file(conn,fsp);
	}
	
	DEBUG(3,("flush\n"));
	END_PROFILE(SMBflush);
	return(outsize);
}

/****************************************************************************
 Reply to a exit.
****************************************************************************/

int reply_exit(connection_struct *conn, 
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize;
	START_PROFILE(SMBexit);

	file_close_pid(SVAL(inbuf,smb_pid));

	outsize = set_message(outbuf,0,0,True);

	DEBUG(3,("exit\n"));

	END_PROFILE(SMBexit);
	return(outsize);
}

/****************************************************************************
 Reply to a close - has to deal with closing a directory opened by NT SMB's.
****************************************************************************/

int reply_close(connection_struct *conn, char *inbuf,char *outbuf, int size,
                int dum_buffsize)
{
	extern struct current_user current_user;
	int outsize = 0;
	time_t mtime;
	int32 eclass = 0, err = 0;
	files_struct *fsp = NULL;
	START_PROFILE(SMBclose);

	outsize = set_message(outbuf,0,0,True);

	/* If it's an IPC, pass off to the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBclose);
		return reply_pipe_close(conn, inbuf,outbuf);
	}

	fsp = file_fsp(inbuf,smb_vwv0);

	/*
	 * We can only use CHECK_FSP if we know it's not a directory.
	 */

	if(!fsp || (fsp->conn != conn) || (fsp->vuid != current_user.vuid)) {
		END_PROFILE(SMBclose);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	if(fsp->is_directory) {
		/*
		 * Special case - close NT SMB directory handle.
		 */
		DEBUG(3,("close %s fnum=%d\n", fsp->is_directory ? "directory" : "stat file open", fsp->fnum));
		close_file(fsp,True);
	} else {
		/*
		 * Close ordinary file.
		 */
		int close_err;
		pstring file_name;

		/* Save the name for time set in close. */
		pstrcpy( file_name, fsp->fsp_name);

		DEBUG(3,("close fd=%d fnum=%d (numopen=%d)\n",
			 fsp->fd, fsp->fnum,
			 conn->num_files_open));
 
		/*
		 * close_file() returns the unix errno if an error
		 * was detected on close - normally this is due to
		 * a disk full error. If not then it was probably an I/O error.
		 */
 
		if((close_err = close_file(fsp,True)) != 0) {
			errno = close_err;
			END_PROFILE(SMBclose);
			return (UNIXERROR(ERRHRD,ERRgeneral));
		}

		/*
		 * Now take care of any time sent in the close.
		 */

		mtime = make_unix_date3(inbuf+smb_vwv1);
		
		/* try and set the date */
		set_filetime(conn, file_name, mtime);

	}  

	/* We have a cached error */
	if(eclass || err) {
		END_PROFILE(SMBclose);
		return ERROR_DOS(eclass,err);
	}

	END_PROFILE(SMBclose);
	return(outsize);
}

/****************************************************************************
 Reply to a writeclose (Core+ protocol).
****************************************************************************/

int reply_writeclose(connection_struct *conn,
		     char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	int close_err = 0;
	SMB_OFF_T startpos;
	char *data;
	time_t mtime;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteclose);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	mtime = make_unix_date3(inbuf+smb_vwv4);
	data = smb_buf(inbuf) + 1;
  
	if (numtowrite && is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteclose);
		return ERROR_DOS(ERRDOS,ERRlock);
	}
  
	nwritten = write_file(fsp,data,startpos,numtowrite);

	set_filetime(conn, fsp->fsp_name,mtime);
  
	/*
	 * More insanity. W2K only closes the file if writelen > 0.
	 * JRA.
	 */

	if (numtowrite) {
		DEBUG(3,("reply_writeclose: zero length write doesn't close file %s\n",
			fsp->fsp_name ));
		close_err = close_file(fsp,True);
	}

	DEBUG(3,("writeclose fnum=%d num=%d wrote=%d (numopen=%d)\n",
		 fsp->fnum, (int)numtowrite, (int)nwritten,
		 conn->num_files_open));
  
	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwriteclose);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}
 
	if(close_err != 0) {
		errno = close_err;
		END_PROFILE(SMBwriteclose);
		return(UNIXERROR(ERRHRD,ERRgeneral));
	}
 
	outsize = set_message(outbuf,1,0,True);
  
	SSVAL(outbuf,smb_vwv0,nwritten);
	END_PROFILE(SMBwriteclose);
	return(outsize);
}

/****************************************************************************
 Reply to a lock.
****************************************************************************/

int reply_lock(connection_struct *conn,
	       char *inbuf,char *outbuf, int length, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	SMB_BIG_UINT count,offset;
	NTSTATUS status;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	BOOL my_lock_ctx = False;

	START_PROFILE(SMBlock);

	CHECK_FSP(fsp,conn);

	release_level_2_oplocks_on_change(fsp);

	count = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv1);
	offset = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv3);

	DEBUG(3,("lock fd=%d fnum=%d offset=%.0f count=%.0f\n",
		 fsp->fd, fsp->fnum, (double)offset, (double)count));

	status = do_lock_spin(fsp, conn, SVAL(inbuf,smb_pid), count, offset, WRITE_LOCK, &my_lock_ctx);
	if (NT_STATUS_V(status)) {
#if 0
		/* Tests using Samba4 against W2K show this call never creates a blocking lock. */
		if (lp_blocking_locks(SNUM(conn)) && !my_lock_ctx && ERROR_WAS_LOCK_DENIED(status)) {
			/*
			 * A blocking lock was requested. Package up
			 * this smb into a queued request and push it
			 * onto the blocking lock queue.
			 */
			if(push_blocking_lock_request(inbuf, length, -1, 0, SVAL(inbuf,smb_pid), offset, count)) {
				END_PROFILE(SMBlock);
				return -1;
			}
		}
#endif
		END_PROFILE(SMBlock);
		return ERROR_NT(status);
	}

	END_PROFILE(SMBlock);
	return(outsize);
}

/****************************************************************************
 Reply to a unlock.
****************************************************************************/

int reply_unlock(connection_struct *conn, char *inbuf,char *outbuf, int size, 
		 int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	SMB_BIG_UINT count,offset;
	NTSTATUS status;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBunlock);

	CHECK_FSP(fsp,conn);
	
	count = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv1);
	offset = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv3);
	
	status = do_unlock(fsp, conn, SVAL(inbuf,smb_pid), count, offset);
	if (NT_STATUS_V(status)) {
		END_PROFILE(SMBunlock);
		return ERROR_NT(status);
	}

	DEBUG( 3, ( "unlock fd=%d fnum=%d offset=%.0f count=%.0f\n",
		    fsp->fd, fsp->fnum, (double)offset, (double)count ) );
	
	END_PROFILE(SMBunlock);
	return(outsize);
}

/****************************************************************************
 Reply to a tdis.
****************************************************************************/

int reply_tdis(connection_struct *conn, 
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	uint16 vuid;
	START_PROFILE(SMBtdis);

	vuid = SVAL(inbuf,smb_uid);

	if (!conn) {
		DEBUG(4,("Invalid connection in tdis\n"));
		END_PROFILE(SMBtdis);
		return ERROR_DOS(ERRSRV,ERRinvnid);
	}

	conn->used = False;

	close_cnum(conn,vuid);
  
	END_PROFILE(SMBtdis);
	return outsize;
}

/****************************************************************************
 Reply to a echo.
****************************************************************************/

int reply_echo(connection_struct *conn,
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int smb_reverb = SVAL(inbuf,smb_vwv0);
	int seq_num;
	unsigned int data_len = smb_buflen(inbuf);
	int outsize = set_message(outbuf,1,data_len,True);
	START_PROFILE(SMBecho);

	if (data_len > BUFFER_SIZE) {
		DEBUG(0,("reply_echo: data_len too large.\n"));
		END_PROFILE(SMBecho);
		return -1;
	}

	/* copy any incoming data back out */
	if (data_len > 0)
		memcpy(smb_buf(outbuf),smb_buf(inbuf),data_len);

	if (smb_reverb > 100) {
		DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
		smb_reverb = 100;
	}

	for (seq_num =1 ; seq_num <= smb_reverb ; seq_num++) {
		SSVAL(outbuf,smb_vwv0,seq_num);

		smb_setlen(outbuf,outsize - 4);

		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_echo: send_smb failed.");
	}

	DEBUG(3,("echo %d times\n", smb_reverb));

	smb_echo_count++;

	END_PROFILE(SMBecho);
	return -1;
}

/****************************************************************************
 Reply to a printopen.
****************************************************************************/

int reply_printopen(connection_struct *conn, 
		    char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	files_struct *fsp;
	START_PROFILE(SMBsplopen);
	
	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplopen);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	/* Open for exclusive use, write only. */
	fsp = print_fsp_open(conn, NULL);

	if (!fsp) {
		END_PROFILE(SMBsplopen);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);
  
	DEBUG(3,("openprint fd=%d fnum=%d\n",
		 fsp->fd, fsp->fnum));

	END_PROFILE(SMBsplopen);
	return(outsize);
}

/****************************************************************************
 Reply to a printclose.
****************************************************************************/

int reply_printclose(connection_struct *conn,
		     char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int close_err = 0;
	START_PROFILE(SMBsplclose);

	CHECK_FSP(fsp,conn);

	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplclose);
		return ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	}
  
	DEBUG(3,("printclose fd=%d fnum=%d\n",
		 fsp->fd,fsp->fnum));
  
	close_err = close_file(fsp,True);

	if(close_err != 0) {
		errno = close_err;
		END_PROFILE(SMBsplclose);
		return(UNIXERROR(ERRHRD,ERRgeneral));
	}

	END_PROFILE(SMBsplclose);
	return(outsize);
}

/****************************************************************************
 Reply to a printqueue.
****************************************************************************/

int reply_printqueue(connection_struct *conn,
		     char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,2,3,True);
	int max_count = SVAL(inbuf,smb_vwv0);
	int start_index = SVAL(inbuf,smb_vwv1);
	START_PROFILE(SMBsplretq);

	/* we used to allow the client to get the cnum wrong, but that
	   is really quite gross and only worked when there was only
	   one printer - I think we should now only accept it if they
	   get it right (tridge) */
	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplretq);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	SSVAL(outbuf,smb_vwv0,0);
	SSVAL(outbuf,smb_vwv1,0);
	SCVAL(smb_buf(outbuf),0,1);
	SSVAL(smb_buf(outbuf),1,0);
  
	DEBUG(3,("printqueue start_index=%d max_count=%d\n",
		 start_index, max_count));

	{
		print_queue_struct *queue = NULL;
		print_status_struct status;
		char *p = smb_buf(outbuf) + 3;
		int count = print_queue_status(SNUM(conn), &queue, &status);
		int num_to_get = ABS(max_count);
		int first = (max_count>0?start_index:start_index+max_count+1);
		int i;

		if (first >= count)
			num_to_get = 0;
		else
			num_to_get = MIN(num_to_get,count-first);
    

		for (i=first;i<first+num_to_get;i++) {
			put_dos_date2(p,0,queue[i].time);
			SCVAL(p,4,(queue[i].status==LPQ_PRINTING?2:3));
			SSVAL(p,5, queue[i].job);
			SIVAL(p,7,queue[i].size);
			SCVAL(p,11,0);
			srvstr_push(outbuf, p+12, queue[i].fs_user, 16, STR_ASCII);
			p += 28;
		}

		if (count > 0) {
			outsize = set_message(outbuf,2,28*count+3,False); 
			SSVAL(outbuf,smb_vwv0,count);
			SSVAL(outbuf,smb_vwv1,(max_count>0?first+count:first-1));
			SCVAL(smb_buf(outbuf),0,1);
			SSVAL(smb_buf(outbuf),1,28*count);
		}

		SAFE_FREE(queue);
	  
		DEBUG(3,("%d entries returned in queue\n",count));
	}
  
	END_PROFILE(SMBsplretq);
	return(outsize);
}

/****************************************************************************
 Reply to a printwrite.
****************************************************************************/

int reply_printwrite(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int numtowrite;
	int outsize = set_message(outbuf,0,0,True);
	char *data;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);

	START_PROFILE(SMBsplwr);
  
	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplwr);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(smb_buf(inbuf),1);
	data = smb_buf(inbuf) + 3;
  
	if (write_file(fsp,data,-1,numtowrite) != numtowrite) {
		END_PROFILE(SMBsplwr);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	DEBUG( 3, ( "printwrite fnum=%d num=%d\n", fsp->fnum, numtowrite ) );
  
	END_PROFILE(SMBsplwr);
	return(outsize);
}

/****************************************************************************
 The guts of the mkdir command, split out so it may be called by the NT SMB
 code. 
****************************************************************************/

NTSTATUS mkdir_internal(connection_struct *conn, pstring directory)
{
	BOOL bad_path = False;
	SMB_STRUCT_STAT sbuf;
	int ret= -1;
	
	unix_convert(directory,conn,0,&bad_path,&sbuf);

	if( strchr_m(directory, ':')) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	if (ms_has_wild(directory)) {
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	if (check_name(directory, conn))
		ret = vfs_MkDir(conn,directory,unix_mode(conn,aDIR,directory));
	
	if (ret == -1) {
	        if(errno == ENOENT) {
			if (bad_path)
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			else
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		return map_nt_error_from_unix(errno);
	}
	
	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a mkdir.
****************************************************************************/

int reply_mkdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring directory;
	int outsize;
	NTSTATUS status;
	START_PROFILE(SMBmkdir);
 
	srvstr_get_path(inbuf, directory, smb_buf(inbuf) + 1, sizeof(directory), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBmkdir);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(directory, conn, inbuf, outbuf);

	status = mkdir_internal(conn, directory);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBmkdir);
		return ERROR_NT(status);
	}

	outsize = set_message(outbuf,0,0,True);

	DEBUG( 3, ( "mkdir %s ret=%d\n", directory, outsize ) );

	END_PROFILE(SMBmkdir);
	return(outsize);
}

/****************************************************************************
 Static function used by reply_rmdir to delete an entire directory
 tree recursively. Return False on ok, True on fail.
****************************************************************************/

static BOOL recursive_rmdir(connection_struct *conn, char *directory)
{
	const char *dname = NULL;
	BOOL ret = False;
	void *dirptr = OpenDir(conn, directory, False);

	if(dirptr == NULL)
		return True;

	while((dname = ReadDirName(dirptr))) {
		pstring fullname;
		SMB_STRUCT_STAT st;

		if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
			continue;

		/* Construct the full name. */
		if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname)) {
			errno = ENOMEM;
			ret = True;
			break;
		}

		pstrcpy(fullname, directory);
		pstrcat(fullname, "/");
		pstrcat(fullname, dname);

		if(SMB_VFS_LSTAT(conn,fullname, &st) != 0) {
			ret = True;
			break;
		}

		if(st.st_mode & S_IFDIR) {
			if(recursive_rmdir(conn, fullname)!=0) {
				ret = True;
				break;
			}
			if(SMB_VFS_RMDIR(conn,fullname) != 0) {
				ret = True;
				break;
			}
		} else if(SMB_VFS_UNLINK(conn,fullname) != 0) {
			ret = True;
			break;
		}
	}
	CloseDir(dirptr);
	return ret;
}

/****************************************************************************
 The internals of the rmdir code - called elsewhere.
****************************************************************************/

BOOL rmdir_internals(connection_struct *conn, char *directory)
{
	BOOL ok;

	ok = (SMB_VFS_RMDIR(conn,directory) == 0);
	if(!ok && ((errno == ENOTEMPTY)||(errno == EEXIST)) && lp_veto_files(SNUM(conn))) {
		/* 
		 * Check to see if the only thing in this directory are
		 * vetoed files/directories. If so then delete them and
		 * retry. If we fail to delete any of them (and we *don't*
		 * do a recursive delete) then fail the rmdir.
		 */
		BOOL all_veto_files = True;
		const char *dname;
		void *dirptr = OpenDir(conn, directory, False);

		if(dirptr != NULL) {
			int dirpos = TellDir(dirptr);
			while ((dname = ReadDirName(dirptr))) {
				if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
					continue;
				if(!IS_VETO_PATH(conn, dname)) {
					all_veto_files = False;
					break;
				}
			}

			if(all_veto_files) {
				SeekDir(dirptr,dirpos);
				while ((dname = ReadDirName(dirptr))) {
					pstring fullname;
					SMB_STRUCT_STAT st;

					if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
						continue;

					/* Construct the full name. */
					if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname)) {
						errno = ENOMEM;
						break;
					}

					pstrcpy(fullname, directory);
					pstrcat(fullname, "/");
					pstrcat(fullname, dname);
                     
					if(SMB_VFS_LSTAT(conn,fullname, &st) != 0)
						break;
					if(st.st_mode & S_IFDIR) {
						if(lp_recursive_veto_delete(SNUM(conn))) {
							if(recursive_rmdir(conn, fullname) != 0)
								break;
						}
						if(SMB_VFS_RMDIR(conn,fullname) != 0)
							break;
					} else if(SMB_VFS_UNLINK(conn,fullname) != 0)
						break;
				}
				CloseDir(dirptr);
				/* Retry the rmdir */
				ok = (SMB_VFS_RMDIR(conn,directory) == 0);
			} else {
				CloseDir(dirptr);
			}
		} else {
			errno = ENOTEMPTY;
		}
	}

	if (!ok)
		DEBUG(3,("rmdir_internals: couldn't remove directory %s : %s\n", directory,strerror(errno)));

	return ok;
}

/****************************************************************************
 Reply to a rmdir.
****************************************************************************/

int reply_rmdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring directory;
	int outsize = 0;
	BOOL ok = False;
	BOOL bad_path = False;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;
	START_PROFILE(SMBrmdir);

	srvstr_get_path(inbuf, directory, smb_buf(inbuf) + 1, sizeof(directory), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBrmdir);
		return ERROR_NT(status);
	}

	RESOLVE_DFSPATH(directory, conn, inbuf, outbuf)

	unix_convert(directory,conn, NULL,&bad_path,&sbuf);
  
	if (check_name(directory,conn)) {
		dptr_closepath(directory,SVAL(inbuf,smb_pid));
		ok = rmdir_internals(conn, directory);
	}
  
	if (!ok) {
		END_PROFILE(SMBrmdir);
		return set_bad_path_error(errno, bad_path, outbuf, ERRDOS, ERRbadpath);
	}
 
	outsize = set_message(outbuf,0,0,True);
  
	DEBUG( 3, ( "rmdir %s\n", directory ) );
  
	END_PROFILE(SMBrmdir);
	return(outsize);
}

/*******************************************************************
 Resolve wildcards in a filename rename.
 Note that name is in UNIX charset and thus potentially can be more
 than fstring buffer (255 bytes) especially in default UTF-8 case.
 Therefore, we use pstring inside and all calls should ensure that
 name2 is at least pstring-long (they do already)
********************************************************************/

static BOOL resolve_wildcards(const char *name1, char *name2)
{
	pstring root1,root2;
	pstring ext1,ext2;
	char *p,*p2, *pname1, *pname2;
	int available_space, actual_space;
	

	pname1 = strrchr_m(name1,'/');
	pname2 = strrchr_m(name2,'/');

	if (!pname1 || !pname2)
		return(False);
  
	pstrcpy(root1,pname1);
	pstrcpy(root2,pname2);
	p = strrchr_m(root1,'.');
	if (p) {
		*p = 0;
		pstrcpy(ext1,p+1);
	} else {
		pstrcpy(ext1,"");    
	}
	p = strrchr_m(root2,'.');
	if (p) {
		*p = 0;
		pstrcpy(ext2,p+1);
	} else {
		pstrcpy(ext2,"");    
	}

	p = root1;
	p2 = root2;
	while (*p2) {
		if (*p2 == '?') {
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			pstrcpy(p2, p);
			break;
		} else {
			p2++;
		}
		if (*p)
			p++;
	}

	p = ext1;
	p2 = ext2;
	while (*p2) {
		if (*p2 == '?') {
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			pstrcpy(p2, p);
			break;
		} else {
			p2++;
		}
		if (*p)
			p++;
	}

	available_space = sizeof(pstring) - PTR_DIFF(pname2, name2);
	
	if (ext2[0]) {
		actual_space = snprintf(pname2, available_space - 1, "%s.%s", root2, ext2);
		if (actual_space >= available_space - 1) {
			DEBUG(1,("resolve_wildcards: can't fit resolved name into specified buffer (overrun by %d bytes)\n",
				actual_space - available_space));
		}
	} else {
		pstrcpy_base(pname2, root2, name2);
	}

	return(True);
}

/****************************************************************************
 Ensure open files have their names updates.
****************************************************************************/

static void rename_open_files(connection_struct *conn, SMB_DEV_T dev, SMB_INO_T inode, char *newname)
{
	files_struct *fsp;
	BOOL did_rename = False;

	for(fsp = file_find_di_first(dev, inode); fsp; fsp = file_find_di_next(fsp)) {
		DEBUG(10,("rename_open_files: renaming file fnum %d (dev = %x, inode = %.0f) from %s -> %s\n",
			fsp->fnum, (unsigned int)fsp->dev, (double)fsp->inode,
			fsp->fsp_name, newname ));
		string_set(&fsp->fsp_name, newname);
		did_rename = True;
	}

	if (!did_rename)
		DEBUG(10,("rename_open_files: no open files on dev %x, inode %.0f for %s\n",
			(unsigned int)dev, (double)inode, newname ));
}

/****************************************************************************
 Rename an open file - given an fsp.
****************************************************************************/

NTSTATUS rename_internals_fsp(connection_struct *conn, files_struct *fsp, char *newname, BOOL replace_if_exists)
{
	SMB_STRUCT_STAT sbuf;
	BOOL bad_path = False;
	pstring newname_last_component;
	NTSTATUS error = NT_STATUS_OK;
	BOOL dest_exists;
	BOOL rcdest = True;

	ZERO_STRUCT(sbuf);
	rcdest = unix_convert(newname,conn,newname_last_component,&bad_path,&sbuf);

	/* Quick check for "." and ".." */
	if (!bad_path && newname_last_component[0] == '.') {
		if (!newname_last_component[1] || (newname_last_component[1] == '.' && !newname_last_component[2])) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	if (!rcdest && bad_path) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Ensure newname contains a '/' */
	if(strrchr_m(newname,'/') == 0) {
		pstring tmpstr;
		
		pstrcpy(tmpstr, "./");
		pstrcat(tmpstr, newname);
		pstrcpy(newname, tmpstr);
	}

	/*
	 * Check for special case with case preserving and not
	 * case sensitive. If the old last component differs from the original
	 * last component only by case, then we should allow
	 * the rename (user is trying to change the case of the
	 * filename).
	 */

	if((case_sensitive == False) && (case_preserve == True) &&
			strequal(newname, fsp->fsp_name)) {
		char *p;
		pstring newname_modified_last_component;

		/*
		 * Get the last component of the modified name.
		 * Note that we guarantee that newname contains a '/'
		 * character above.
		 */
		p = strrchr_m(newname,'/');
		pstrcpy(newname_modified_last_component,p+1);
			
		if(strcsequal(newname_modified_last_component, 
			      newname_last_component) == False) {
			/*
			 * Replace the modified last component with
			 * the original.
			 */
			pstrcpy(p+1, newname_last_component);
		}
	}

	/*
	 * If the src and dest names are identical - including case,
	 * don't do the rename, just return success.
	 */

	if (strcsequal(fsp->fsp_name, newname)) {
		DEBUG(3,("rename_internals_fsp: identical names in rename %s - returning success\n",
			newname));
		return NT_STATUS_OK;
	}

	dest_exists = vfs_object_exist(conn,newname,NULL);

	if(!replace_if_exists && dest_exists) {
		DEBUG(3,("rename_internals_fsp: dest exists doing rename %s -> %s\n",
			fsp->fsp_name,newname));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	error = can_rename(newname,conn,&sbuf);

	if (dest_exists && !NT_STATUS_IS_OK(error)) {
		DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
			nt_errstr(error), fsp->fsp_name,newname));
		if (NT_STATUS_EQUAL(error,NT_STATUS_SHARING_VIOLATION))
			error = NT_STATUS_ACCESS_DENIED;
		return error;
	}

	if(SMB_VFS_RENAME(conn,fsp->fsp_name, newname) == 0) {
		DEBUG(3,("rename_internals_fsp: succeeded doing rename on %s -> %s\n",
			fsp->fsp_name,newname));
		rename_open_files(conn, fsp->dev, fsp->inode, newname);
		return NT_STATUS_OK;	
	}

	if (errno == ENOTDIR || errno == EISDIR)
		error = NT_STATUS_OBJECT_NAME_COLLISION;
	else
		error = map_nt_error_from_unix(errno);
		
	DEBUG(3,("rename_internals_fsp: Error %s rename %s -> %s\n",
		nt_errstr(error), fsp->fsp_name,newname));

	return error;
}

/****************************************************************************
 The guts of the rename command, split out so it may be called by the NT SMB
 code. 
****************************************************************************/

NTSTATUS rename_internals(connection_struct *conn, char *name, char *newname, uint16 attrs, BOOL replace_if_exists)
{
	pstring directory;
	pstring mask;
	pstring last_component_src;
	pstring last_component_dest;
	char *p;
	BOOL has_wild;
	BOOL bad_path_src = False;
	BOOL bad_path_dest = False;
	int count=0;
	NTSTATUS error = NT_STATUS_OK;
	BOOL rc = True;
	BOOL rcdest = True;
	SMB_STRUCT_STAT sbuf1, sbuf2;

	*directory = *mask = 0;

	ZERO_STRUCT(sbuf1);
	ZERO_STRUCT(sbuf2);

	rc = unix_convert(name,conn,last_component_src,&bad_path_src,&sbuf1);
	if (!rc && bad_path_src) {
		if (ms_has_wild(last_component_src))
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Quick check for "." and ".." */
	if (last_component_src[0] == '.') {
		if (!last_component_src[1] || (last_component_src[1] == '.' && !last_component_src[2])) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
	}

	rcdest = unix_convert(newname,conn,last_component_dest,&bad_path_dest,&sbuf2);

	/* Quick check for "." and ".." */
	if (last_component_dest[0] == '.') {
		if (!last_component_dest[1] || (last_component_dest[1] == '.' && !last_component_dest[2])) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
	}

	/*
	 * Split the old name into directory and last component
	 * strings. Note that unix_convert may have stripped off a 
	 * leading ./ from both name and newname if the rename is 
	 * at the root of the share. We need to make sure either both
	 * name and newname contain a / character or neither of them do
	 * as this is checked in resolve_wildcards().
	 */

	p = strrchr_m(name,'/');
	if (!p) {
		pstrcpy(directory,".");
		pstrcpy(mask,name);
	} else {
		*p = 0;
		pstrcpy(directory,name);
		pstrcpy(mask,p+1);
		*p = '/'; /* Replace needed for exceptional test below. */
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!rc && mangle_is_mangled(mask))
		mangle_check_cache( mask );

	has_wild = ms_has_wild(mask);

	if (!has_wild) {
		/*
		 * No wildcards - just process the one file.
		 */
		BOOL is_short_name = mangle_is_8_3(name, True);

		/* Add a terminating '/' to the directory name. */
		pstrcat(directory,"/");
		pstrcat(directory,mask);
		
		/* Ensure newname contains a '/' also */
		if(strrchr_m(newname,'/') == 0) {
			pstring tmpstr;
			
			pstrcpy(tmpstr, "./");
			pstrcat(tmpstr, newname);
			pstrcpy(newname, tmpstr);
		}
		
		DEBUG(3,("rename_internals: case_sensitive = %d, case_preserve = %d, short case preserve = %d, \
directory = %s, newname = %s, last_component_dest = %s, is_8_3 = %d\n", 
			 case_sensitive, case_preserve, short_case_preserve, directory, 
			 newname, last_component_dest, is_short_name));

		/*
		 * Check for special case with case preserving and not
		 * case sensitive, if directory and newname are identical,
		 * and the old last component differs from the original
		 * last component only by case, then we should allow
		 * the rename (user is trying to change the case of the
		 * filename).
		 */
		if((case_sensitive == False) && 
		   (((case_preserve == True) && 
		     (is_short_name == False)) || 
		    ((short_case_preserve == True) && 
		     (is_short_name == True))) &&
		   strcsequal(directory, newname)) {
			pstring modified_last_component;

			/*
			 * Get the last component of the modified name.
			 * Note that we guarantee that newname contains a '/'
			 * character above.
			 */
			p = strrchr_m(newname,'/');
			pstrcpy(modified_last_component,p+1);
			
			if(strcsequal(modified_last_component, 
				      last_component_dest) == False) {
				/*
				 * Replace the modified last component with
				 * the original.
				 */
				pstrcpy(p+1, last_component_dest);
			}
		}
	
		resolve_wildcards(directory,newname);
	
		/*
		 * The source object must exist.
		 */

		if (!vfs_object_exist(conn, directory, &sbuf1)) {
			DEBUG(3,("rename_internals: source doesn't exist doing rename %s -> %s\n",
				directory,newname));

			if (errno == ENOTDIR || errno == EISDIR || errno == ENOENT) {
				/*
				 * Must return different errors depending on whether the parent
				 * directory existed or not.
				 */

				p = strrchr_m(directory, '/');
				if (!p)
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				*p = '\0';
				if (vfs_object_exist(conn, directory, NULL))
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
			error = map_nt_error_from_unix(errno);
			DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
				nt_errstr(error), directory,newname));

			return error;
		}

		if (!rcdest && bad_path_dest) {
			if (ms_has_wild(last_component_dest))
				return NT_STATUS_OBJECT_NAME_INVALID;
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}

		error = can_rename(directory,conn,&sbuf1);

		if (!NT_STATUS_IS_OK(error)) {
			DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
				nt_errstr(error), directory,newname));
			return error;
		}

		/*
		 * If the src and dest names are identical - including case,
		 * don't do the rename, just return success.
		 */

		if (strcsequal(directory, newname)) {
			rename_open_files(conn, sbuf1.st_dev, sbuf1.st_ino, newname);
			DEBUG(3,("rename_internals: identical names in rename %s - returning success\n", directory));
			return NT_STATUS_OK;
		}

		if(!replace_if_exists && vfs_object_exist(conn,newname,NULL)) {
			DEBUG(3,("rename_internals: dest exists doing rename %s -> %s\n",
				directory,newname));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if(SMB_VFS_RENAME(conn,directory, newname) == 0) {
			DEBUG(3,("rename_internals: succeeded doing rename on %s -> %s\n",
				directory,newname));
			rename_open_files(conn, sbuf1.st_dev, sbuf1.st_ino, newname);
			return NT_STATUS_OK;	
		}

		if (errno == ENOTDIR || errno == EISDIR)
			error = NT_STATUS_OBJECT_NAME_COLLISION;
		else
			error = map_nt_error_from_unix(errno);
		
		DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
			nt_errstr(error), directory,newname));

		return error;
	} else {
		/*
		 * Wildcards - process each file that matches.
		 */
		void *dirptr = NULL;
		const char *dname;
		pstring destname;
		
		if (check_name(directory,conn))
			dirptr = OpenDir(conn, directory, True);
		
		if (dirptr) {
			error = NT_STATUS_NO_SUCH_FILE;
/*			Was error = NT_STATUS_OBJECT_NAME_NOT_FOUND; - gentest fix. JRA */
			
			if (strequal(mask,"????????.???"))
				pstrcpy(mask,"*");
			
			while ((dname = ReadDirName(dirptr))) {
				pstring fname;
				BOOL sysdir_entry = False;

				pstrcpy(fname,dname);
				
				/* Quick check for "." and ".." */
				if (fname[0] == '.') {
					if (!fname[1] || (fname[1] == '.' && !fname[2])) {
						if (attrs & aDIR) {
							sysdir_entry = True;
						} else {
							continue;
						}
					}
				}

				if(!mask_match(fname, mask, case_sensitive))
					continue;
				
				if (sysdir_entry) {
					error = NT_STATUS_OBJECT_NAME_INVALID;
					break;
				}

				error = NT_STATUS_ACCESS_DENIED;
				slprintf(fname,sizeof(fname)-1,"%s/%s",directory,dname);
				if (!vfs_object_exist(conn, fname, &sbuf1)) {
					error = NT_STATUS_OBJECT_NAME_NOT_FOUND;
					DEBUG(6,("rename %s failed. Error %s\n", fname, nt_errstr(error)));
					continue;
				}
				error = can_rename(fname,conn,&sbuf1);
				if (!NT_STATUS_IS_OK(error)) {
					DEBUG(6,("rename %s refused\n", fname));
					continue;
				}
				pstrcpy(destname,newname);
				
				if (!resolve_wildcards(fname,destname)) {
					DEBUG(6,("resolve_wildcards %s %s failed\n", 
                                                 fname, destname));
					continue;
				}
				
				if (strcsequal(fname,destname)) {
					rename_open_files(conn, sbuf1.st_dev, sbuf1.st_ino, newname);
					DEBUG(3,("rename_internals: identical names in wildcard rename %s - success\n", fname));
					count++;
					error = NT_STATUS_OK;
					continue;
				}

				if (!replace_if_exists && 
                                    vfs_file_exist(conn,destname, NULL)) {
					DEBUG(6,("file_exist %s\n", destname));
					error = NT_STATUS_OBJECT_NAME_COLLISION;
					continue;
				}
				
				if (!SMB_VFS_RENAME(conn,fname,destname)) {
					rename_open_files(conn, sbuf1.st_dev, sbuf1.st_ino, newname);
					count++;
					error = NT_STATUS_OK;
				}
				DEBUG(3,("rename_internals: doing rename on %s -> %s\n",fname,destname));
			}
			CloseDir(dirptr);
		}

		if (!NT_STATUS_EQUAL(error,NT_STATUS_NO_SUCH_FILE)) {
			if (!rcdest && bad_path_dest) {
				if (ms_has_wild(last_component_dest))
					return NT_STATUS_OBJECT_NAME_INVALID;
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
		}
	}
	
	if (count == 0 && NT_STATUS_IS_OK(error)) {
		error = map_nt_error_from_unix(errno);
	}
	
	return error;
}

/****************************************************************************
 Reply to a mv.
****************************************************************************/

int reply_mv(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, 
	     int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	pstring newname;
	char *p;
	uint16 attrs = SVAL(inbuf,smb_vwv0);
	NTSTATUS status;

	START_PROFILE(SMBmv);

	p = smb_buf(inbuf) + 1;
	p += srvstr_get_path(inbuf, name, p, sizeof(name), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBmv);
		return ERROR_NT(status);
	}
	p++;
	p += srvstr_get_path(inbuf, newname, p, sizeof(newname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBmv);
		return ERROR_NT(status);
	}
	
	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);
	RESOLVE_DFSPATH(newname, conn, inbuf, outbuf);
	
	DEBUG(3,("reply_mv : %s -> %s\n",name,newname));
	
	status = rename_internals(conn, name, newname, attrs, False);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBmv);
		return ERROR_NT(status);
	}

	/*
	 * Win2k needs a changenotify request response before it will
	 * update after a rename..
	 */	
	process_pending_change_notify_queue((time_t)0);
	outsize = set_message(outbuf,0,0,True);
  
	END_PROFILE(SMBmv);
	return(outsize);
}

/*******************************************************************
 Copy a file as part of a reply_copy.
******************************************************************/

static BOOL copy_file(char *src,char *dest1,connection_struct *conn, int ofun,
		      int count,BOOL target_is_directory, int *err_ret)
{
	int Access,action;
	SMB_STRUCT_STAT src_sbuf, sbuf2;
	SMB_OFF_T ret=-1;
	files_struct *fsp1,*fsp2;
	pstring dest;
 	uint32 dosattrs;
 
	*err_ret = 0;

	pstrcpy(dest,dest1);
	if (target_is_directory) {
		char *p = strrchr_m(src,'/');
		if (p) 
			p++;
		else
			p = src;
		pstrcat(dest,"/");
		pstrcat(dest,p);
	}

	if (!vfs_file_exist(conn,src,&src_sbuf))
		return(False);

	fsp1 = open_file_shared(conn,src,&src_sbuf,SET_DENY_MODE(DENY_NONE)|SET_OPEN_MODE(DOS_OPEN_RDONLY),
					(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),FILE_ATTRIBUTE_NORMAL,0,&Access,&action);

	if (!fsp1)
		return(False);

	if (!target_is_directory && count)
		ofun = FILE_EXISTS_OPEN;

	dosattrs = dos_mode(conn, src, &src_sbuf);
	if (SMB_VFS_STAT(conn,dest,&sbuf2) == -1)
		ZERO_STRUCTP(&sbuf2);

	fsp2 = open_file_shared(conn,dest,&sbuf2,SET_DENY_MODE(DENY_NONE)|SET_OPEN_MODE(DOS_OPEN_WRONLY),
			ofun,dosattrs,0,&Access,&action);

	if (!fsp2) {
		close_file(fsp1,False);
		return(False);
	}

	if ((ofun&3) == 1) {
		if(SMB_VFS_LSEEK(fsp2,fsp2->fd,0,SEEK_END) == -1) {
			DEBUG(0,("copy_file: error - vfs lseek returned error %s\n", strerror(errno) ));
			/*
			 * Stop the copy from occurring.
			 */
			ret = -1;
			src_sbuf.st_size = 0;
		}
	}
  
	if (src_sbuf.st_size)
		ret = vfs_transfer_file(fsp1, fsp2, src_sbuf.st_size);

	close_file(fsp1,False);

	/* Ensure the modtime is set correctly on the destination file. */
	fsp2->pending_modtime = src_sbuf.st_mtime;

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	*err_ret = close_file(fsp2,False);

	return(ret == (SMB_OFF_T)src_sbuf.st_size);
}

/****************************************************************************
 Reply to a file copy.
****************************************************************************/

int reply_copy(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	pstring directory;
	pstring mask,newname;
	char *p;
	int count=0;
	int error = ERRnoaccess;
	int err = 0;
	BOOL has_wild;
	BOOL exists=False;
	int tid2 = SVAL(inbuf,smb_vwv0);
	int ofun = SVAL(inbuf,smb_vwv1);
	int flags = SVAL(inbuf,smb_vwv2);
	BOOL target_is_directory=False;
	BOOL bad_path1 = False;
	BOOL bad_path2 = False;
	BOOL rc = True;
	SMB_STRUCT_STAT sbuf1, sbuf2;
	NTSTATUS status;

	START_PROFILE(SMBcopy);

	*directory = *mask = 0;

	p = smb_buf(inbuf);
	p += srvstr_get_path(inbuf, name, p, sizeof(name), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcopy);
		return ERROR_NT(status);
	}
	p += srvstr_get_path(inbuf, newname, p, sizeof(newname), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcopy);
		return ERROR_NT(status);
	}
   
	DEBUG(3,("reply_copy : %s -> %s\n",name,newname));
   
	if (tid2 != conn->cnum) {
		/* can't currently handle inter share copies XXXX */
		DEBUG(3,("Rejecting inter-share copy\n"));
		END_PROFILE(SMBcopy);
		return ERROR_DOS(ERRSRV,ERRinvdevice);
	}

	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);
	RESOLVE_DFSPATH(newname, conn, inbuf, outbuf);

	rc = unix_convert(name,conn,0,&bad_path1,&sbuf1);
	unix_convert(newname,conn,0,&bad_path2,&sbuf2);

	target_is_directory = VALID_STAT_OF_DIR(sbuf2);

	if ((flags&1) && target_is_directory) {
		END_PROFILE(SMBcopy);
		return ERROR_DOS(ERRDOS,ERRbadfile);
	}

	if ((flags&2) && !target_is_directory) {
		END_PROFILE(SMBcopy);
		return ERROR_DOS(ERRDOS,ERRbadpath);
	}

	if ((flags&(1<<5)) && VALID_STAT_OF_DIR(sbuf1)) {
		/* wants a tree copy! XXXX */
		DEBUG(3,("Rejecting tree copy\n"));
		END_PROFILE(SMBcopy);
		return ERROR_DOS(ERRSRV,ERRerror);
	}

	p = strrchr_m(name,'/');
	if (!p) {
		pstrcpy(directory,"./");
		pstrcpy(mask,name);
	} else {
		*p = 0;
		pstrcpy(directory,name);
		pstrcpy(mask,p+1);
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!rc && mangle_is_mangled(mask))
		mangle_check_cache( mask );

	has_wild = ms_has_wild(mask);

	if (!has_wild) {
		pstrcat(directory,"/");
		pstrcat(directory,mask);
		if (resolve_wildcards(directory,newname) &&
				copy_file(directory,newname,conn,ofun, count,target_is_directory,&err))
			count++;
		if(!count && err) {
			errno = err;
			END_PROFILE(SMBcopy);
			return(UNIXERROR(ERRHRD,ERRgeneral));
		}
		if (!count) {
			exists = vfs_file_exist(conn,directory,NULL);
		}
	} else {
		void *dirptr = NULL;
		const char *dname;
		pstring destname;

		if (check_name(directory,conn))
			dirptr = OpenDir(conn, directory, True);

		if (dirptr) {
			error = ERRbadfile;

			if (strequal(mask,"????????.???"))
				pstrcpy(mask,"*");

			while ((dname = ReadDirName(dirptr))) {
				pstring fname;
				pstrcpy(fname,dname);
    
				if(!mask_match(fname, mask, case_sensitive))
					continue;

				error = ERRnoaccess;
				slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
				pstrcpy(destname,newname);
				if (resolve_wildcards(fname,destname) && 
						copy_file(fname,destname,conn,ofun,
						count,target_is_directory,&err))
					count++;
				DEBUG(3,("reply_copy : doing copy on %s -> %s\n",fname,destname));
			}
			CloseDir(dirptr);
		}
	}
  
	if (count == 0) {
		if(err) {
			/* Error on close... */
			errno = err;
			END_PROFILE(SMBcopy);
			return(UNIXERROR(ERRHRD,ERRgeneral));
		}

		if (exists) {
			END_PROFILE(SMBcopy);
			return ERROR_DOS(ERRDOS,error);
		} else {
			if((errno == ENOENT) && (bad_path1 || bad_path2)) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			END_PROFILE(SMBcopy);
			return(UNIXERROR(ERRDOS,error));
		}
	}
  
	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,count);

	END_PROFILE(SMBcopy);
	return(outsize);
}

/****************************************************************************
 Reply to a setdir.
****************************************************************************/

int reply_setdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int snum;
	int outsize = 0;
	BOOL ok = False;
	pstring newdir;
	NTSTATUS status;

	START_PROFILE(pathworks_setdir);
  
	snum = SNUM(conn);
	if (!CAN_SETDIR(snum)) {
		END_PROFILE(pathworks_setdir);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	srvstr_get_path(inbuf, newdir, smb_buf(inbuf) + 1, sizeof(newdir), 0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(pathworks_setdir);
		return ERROR_NT(status);
	}
  
	if (strlen(newdir) == 0) {
		ok = True;
	} else {
		ok = vfs_directory_exist(conn,newdir,NULL);
		if (ok)
			string_set(&conn->connectpath,newdir);
	}
  
	if (!ok) {
		END_PROFILE(pathworks_setdir);
		return ERROR_DOS(ERRDOS,ERRbadpath);
	}
  
	outsize = set_message(outbuf,0,0,True);
	SCVAL(outbuf,smb_reh,CVAL(inbuf,smb_reh));
  
	DEBUG(3,("setdir %s\n", newdir));

	END_PROFILE(pathworks_setdir);
	return(outsize);
}

/****************************************************************************
 Get a lock pid, dealing with large count requests.
****************************************************************************/

uint16 get_lock_pid( char *data, int data_offset, BOOL large_file_format)
{
	if(!large_file_format)
		return SVAL(data,SMB_LPID_OFFSET(data_offset));
	else
		return SVAL(data,SMB_LARGE_LPID_OFFSET(data_offset));
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/

SMB_BIG_UINT get_lock_count( char *data, int data_offset, BOOL large_file_format)
{
	SMB_BIG_UINT count = 0;

	if(!large_file_format) {
		count = (SMB_BIG_UINT)IVAL(data,SMB_LKLEN_OFFSET(data_offset));
	} else {

#if defined(HAVE_LONGLONG)
		count = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) << 32) |
			((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints truncate the
		 * lock count by dropping the top 32 bits.
		 */

		if(IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)) != 0) {
			DEBUG(3,("get_lock_count: truncating lock count (high)0x%x (low)0x%x to just low count.\n",
				(unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)),
				(unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)) ));
				SIVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset),0);
		}

		count = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
	}

	return count;
}

#if !defined(HAVE_LONGLONG)
/****************************************************************************
 Pathetically try and map a 64 bit lock offset into 31 bits. I hate Windows :-).
****************************************************************************/

static uint32 map_lock_offset(uint32 high, uint32 low)
{
	unsigned int i;
	uint32 mask = 0;
	uint32 highcopy = high;
 
	/*
	 * Try and find out how many significant bits there are in high.
	 */
 
	for(i = 0; highcopy; i++)
		highcopy >>= 1;
 
	/*
	 * We use 31 bits not 32 here as POSIX
	 * lock offsets may not be negative.
	 */
 
	mask = (~0) << (31 - i);
 
	if(low & mask)
		return 0; /* Fail. */
 
	high <<= (31 - i);
 
	return (high|low);
}
#endif /* !defined(HAVE_LONGLONG) */

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

SMB_BIG_UINT get_lock_offset( char *data, int data_offset, BOOL large_file_format, BOOL *err)
{
	SMB_BIG_UINT offset = 0;

	*err = False;

	if(!large_file_format) {
		offset = (SMB_BIG_UINT)IVAL(data,SMB_LKOFF_OFFSET(data_offset));
	} else {

#if defined(HAVE_LONGLONG)
		offset = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) << 32) |
				((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints mangle the
		 * lock offset by mapping the top 32 bits onto the lower 32.
		 */
      
		if(IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset)) != 0) {
			uint32 low = IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
			uint32 high = IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset));
			uint32 new_low = 0;

			if((new_low = map_lock_offset(high, low)) == 0) {
				*err = True;
				return (SMB_BIG_UINT)-1;
			}

			DEBUG(3,("get_lock_offset: truncating lock offset (high)0x%x (low)0x%x to offset 0x%x.\n",
				(unsigned int)high, (unsigned int)low, (unsigned int)new_low ));
			SIVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset),0);
			SIVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset),new_low);
		}

		offset = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
	}

	return offset;
}

/****************************************************************************
 Reply to a lockingX request.
****************************************************************************/

int reply_lockingX(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	files_struct *fsp = file_fsp(inbuf,smb_vwv2);
	unsigned char locktype = CVAL(inbuf,smb_vwv3);
	unsigned char oplocklevel = CVAL(inbuf,smb_vwv3+1);
	uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
	uint16 num_locks = SVAL(inbuf,smb_vwv7);
	SMB_BIG_UINT count = 0, offset = 0;
	uint16 lock_pid;
	int32 lock_timeout = IVAL(inbuf,smb_vwv4);
	int i;
	char *data;
	BOOL large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES)?True:False;
	BOOL err;
	BOOL my_lock_ctx = False;
	NTSTATUS status;

	START_PROFILE(SMBlockingX);
	
	CHECK_FSP(fsp,conn);
	
	data = smb_buf(inbuf);

	if (locktype & (LOCKING_ANDX_CANCEL_LOCK | LOCKING_ANDX_CHANGE_LOCKTYPE)) {
		/* we don't support these - and CANCEL_LOCK makes w2k
		   and XP reboot so I don't really want to be
		   compatible! (tridge) */
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}
	
	/* Check if this is an oplock break on a file
	   we have granted an oplock on.
	*/
	if ((locktype & LOCKING_ANDX_OPLOCK_RELEASE)) {
		/* Client can insist on breaking to none. */
		BOOL break_to_none = (oplocklevel == 0);
		
		DEBUG(5,("reply_lockingX: oplock break reply (%u) from client for fnum = %d\n",
			 (unsigned int)oplocklevel, fsp->fnum ));

		/*
		 * Make sure we have granted an exclusive or batch oplock on this file.
		 */
		
		if(!EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
			DEBUG(0,("reply_lockingX: Error : oplock break from client for fnum = %d and \
no oplock granted on this file (%s).\n", fsp->fnum, fsp->fsp_name));

			/* if this is a pure oplock break request then don't send a reply */
			if (num_locks == 0 && num_ulocks == 0) {
				END_PROFILE(SMBlockingX);
				return -1;
			} else {
				END_PROFILE(SMBlockingX);
				return ERROR_DOS(ERRDOS,ERRlock);
			}
		}

		if (remove_oplock(fsp, break_to_none) == False) {
			DEBUG(0,("reply_lockingX: error in removing oplock on file %s\n",
				 fsp->fsp_name ));
		}
		
		/* if this is a pure oplock break request then don't send a reply */
		if (num_locks == 0 && num_ulocks == 0) {
			/* Sanity check - ensure a pure oplock break is not a
			   chained request. */
			if(CVAL(inbuf,smb_vwv0) != 0xff)
				DEBUG(0,("reply_lockingX: Error : pure oplock break is a chained %d request !\n",
					 (unsigned int)CVAL(inbuf,smb_vwv0) ));
			END_PROFILE(SMBlockingX);
			return -1;
		}
	}

	/*
	 * We do this check *after* we have checked this is not a oplock break
	 * response message. JRA.
	 */
	
	release_level_2_oplocks_on_change(fsp);
	
	/* Data now points at the beginning of the list
	   of smb_unlkrng structs */
	for(i = 0; i < (int)num_ulocks; i++) {
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);
		
		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		}

		DEBUG(10,("reply_lockingX: unlock start=%.0f, len=%.0f for pid %u, file %s\n",
			  (double)offset, (double)count, (unsigned int)lock_pid, fsp->fsp_name ));
		
		status = do_unlock(fsp,conn,lock_pid,count,offset);
		if (NT_STATUS_V(status)) {
			END_PROFILE(SMBlockingX);
			return ERROR_NT(status);
		}
	}

	/* Setup the timeout in seconds. */

	lock_timeout = ((lock_timeout == -1) ? -1 : (lock_timeout+999)/1000);
	
	/* Now do any requested locks */
	data += ((large_file_format ? 20 : 10)*num_ulocks);
	
	/* Data now points at the beginning of the list
	   of smb_lkrng structs */
	
	for(i = 0; i < (int)num_locks; i++) {
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);
		
		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		}
		
		DEBUG(10,("reply_lockingX: lock start=%.0f, len=%.0f for pid %u, file %s timeout = %d\n",
			(double)offset, (double)count, (unsigned int)lock_pid,
			fsp->fsp_name, (int)lock_timeout ));
		
		status = do_lock_spin(fsp,conn,lock_pid, count,offset, 
				 ((locktype & 1) ? READ_LOCK : WRITE_LOCK), &my_lock_ctx);
		if (NT_STATUS_V(status)) {
			/*
			 * Interesting fact found by IFSTEST /t LockOverlappedTest...
			 * Even if it's our own lock context, we need to wait here as
			 * there may be an unlock on the way.
			 * So I removed a "&& !my_lock_ctx" from the following
			 * if statement. JRA.
			 */
			if ((lock_timeout != 0) && lp_blocking_locks(SNUM(conn)) && ERROR_WAS_LOCK_DENIED(status)) {
				/*
				 * A blocking lock was requested. Package up
				 * this smb into a queued request and push it
				 * onto the blocking lock queue.
				 */
				if(push_blocking_lock_request(inbuf, length, lock_timeout, i, lock_pid, offset, count)) {
					END_PROFILE(SMBlockingX);
					return -1;
				}
			}
			break;
		}
	}
	
	/* If any of the above locks failed, then we must unlock
	   all of the previous locks (X/Open spec). */
	if (i != num_locks && num_locks != 0) {
		/*
		 * Ensure we don't do a remove on the lock that just failed,
		 * as under POSIX rules, if we have a lock already there, we
		 * will delete it (and we shouldn't) .....
		 */
		for(i--; i >= 0; i--) {
			lock_pid = get_lock_pid( data, i, large_file_format);
			count = get_lock_count( data, i, large_file_format);
			offset = get_lock_offset( data, i, large_file_format, &err);
			
			/*
			 * There is no error code marked "stupid client bug".... :-).
			 */
			if(err) {
				END_PROFILE(SMBlockingX);
				return ERROR_DOS(ERRDOS,ERRnoaccess);
			}
			
			do_unlock(fsp,conn,lock_pid,count,offset);
		}
		END_PROFILE(SMBlockingX);
		return ERROR_NT(status);
	}

	set_message(outbuf,2,0,True);
	
	DEBUG( 3, ( "lockingX fnum=%d type=%d num_locks=%d num_ulocks=%d\n",
		    fsp->fnum, (unsigned int)locktype, num_locks, num_ulocks ) );
	
	END_PROFILE(SMBlockingX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a SMBreadbmpx (read block multiplex) request.
****************************************************************************/

int reply_readbmpx(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	ssize_t nread = -1;
	ssize_t total_read;
	char *data;
	SMB_OFF_T startpos;
	int outsize;
	size_t maxcount;
	int max_per_packet;
	size_t tcount;
	int pad;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBreadBmpx);

	/* this function doesn't seem to work - disable by default */
	if (!lp_readbmpx()) {
		END_PROFILE(SMBreadBmpx);
		return ERROR_DOS(ERRSRV,ERRuseSTD);
	}

	outsize = set_message(outbuf,8,0,True);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
	maxcount = SVAL(inbuf,smb_vwv3);

	data = smb_buf(outbuf);
	pad = ((long)data)%4;
	if (pad)
		pad = 4 - pad;
	data += pad;

	max_per_packet = bufsize-(outsize+pad);
	tcount = maxcount;
	total_read = 0;

	if (is_locked(fsp,conn,(SMB_BIG_UINT)maxcount,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		END_PROFILE(SMBreadBmpx);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	do {
		size_t N = MIN(max_per_packet,tcount-total_read);
  
		nread = read_file(fsp,data,startpos,N);

		if (nread <= 0)
			nread = 0;

		if (nread < (ssize_t)N)
			tcount = total_read + nread;

		set_message(outbuf,8,nread,False);
		SIVAL(outbuf,smb_vwv0,startpos);
		SSVAL(outbuf,smb_vwv2,tcount);
		SSVAL(outbuf,smb_vwv6,nread);
		SSVAL(outbuf,smb_vwv7,smb_offset(data,outbuf));

		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_readbmpx: send_smb failed.");

		total_read += nread;
		startpos += nread;
	} while (total_read < (ssize_t)tcount);

	END_PROFILE(SMBreadBmpx);
	return(-1);
}

/****************************************************************************
 Reply to a SMBsetattrE.
****************************************************************************/

int reply_setattrE(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	struct utimbuf unix_times;
	int outsize = 0;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBsetattrE);

	outsize = set_message(outbuf,0,0,True);

	if(!fsp || (fsp->conn != conn)) {
		END_PROFILE(SMBgetattrE);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	/*
	 * Convert the DOS times into unix times. Ignore create
	 * time as UNIX can't set this.
	 */

	unix_times.actime = make_unix_date2(inbuf+smb_vwv3);
	unix_times.modtime = make_unix_date2(inbuf+smb_vwv5);
  
	/* 
	 * Patch from Ray Frush <frush@engr.colostate.edu>
	 * Sometimes times are sent as zero - ignore them.
	 */

	if ((unix_times.actime == 0) && (unix_times.modtime == 0)) {
		/* Ignore request */
		if( DEBUGLVL( 3 ) ) {
			dbgtext( "reply_setattrE fnum=%d ", fsp->fnum);
			dbgtext( "ignoring zero request - not setting timestamps of 0\n" );
		}
		END_PROFILE(SMBsetattrE);
		return(outsize);
	} else if ((unix_times.actime != 0) && (unix_times.modtime == 0)) {
		/* set modify time = to access time if modify time was 0 */
		unix_times.modtime = unix_times.actime;
	}

	/* Set the date on this file */
	if(file_utime(conn, fsp->fsp_name, &unix_times)) {
		END_PROFILE(SMBsetattrE);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}
  
	DEBUG( 3, ( "reply_setattrE fnum=%d actime=%d modtime=%d\n",
		fsp->fnum, (int)unix_times.actime, (int)unix_times.modtime ) );

	END_PROFILE(SMBsetattrE);
	return(outsize);
}


/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBwritebmpx (write block multiplex primary) request.
****************************************************************************/

int reply_writebmpx(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t tcount;
	BOOL write_through;
	int smb_doff;
	char *data;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteBmpx);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);
	CHECK_ERROR(fsp);

	tcount = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	write_through = BITSETW(inbuf+smb_vwv7,0);
	numtowrite = SVAL(inbuf,smb_vwv10);
	smb_doff = SVAL(inbuf,smb_vwv11);

	data = smb_base(inbuf) + smb_doff;

	/* If this fails we need to send an SMBwriteC response,
		not an SMBwritebmpx - set this up now so we don't forget */
	SCVAL(outbuf,smb_com,SMBwritec);

	if (is_locked(fsp,conn,(SMB_BIG_UINT)tcount,(SMB_BIG_UINT)startpos,WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteBmpx);
		return(ERROR_DOS(ERRDOS,ERRlock));
	}

	nwritten = write_file(fsp,data,startpos,numtowrite);

	if(lp_syncalways(SNUM(conn)) || write_through)
		sync_file(conn,fsp);
  
	if(nwritten < (ssize_t)numtowrite) {
		END_PROFILE(SMBwriteBmpx);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	/* If the maximum to be written to this file
		is greater than what we just wrote then set
		up a secondary struct to be attached to this
		fd, we will use this to cache error messages etc. */

	if((ssize_t)tcount > nwritten) {
		write_bmpx_struct *wbms;
		if(fsp->wbmpx_ptr != NULL)
			wbms = fsp->wbmpx_ptr; /* Use an existing struct */
		else
			wbms = (write_bmpx_struct *)malloc(sizeof(write_bmpx_struct));
		if(!wbms) {
			DEBUG(0,("Out of memory in reply_readmpx\n"));
			END_PROFILE(SMBwriteBmpx);
			return(ERROR_DOS(ERRSRV,ERRnoresource));
		}
		wbms->wr_mode = write_through;
		wbms->wr_discard = False; /* No errors yet */
		wbms->wr_total_written = nwritten;
		wbms->wr_errclass = 0;
		wbms->wr_error = 0;
		fsp->wbmpx_ptr = wbms;
	}

	/* We are returning successfully, set the message type back to
		SMBwritebmpx */
	SCVAL(outbuf,smb_com,SMBwriteBmpx);
  
	outsize = set_message(outbuf,1,0,True);
  
	SSVALS(outbuf,smb_vwv0,-1); /* We don't support smb_remaining */
  
	DEBUG( 3, ( "writebmpx fnum=%d num=%d wrote=%d\n",
			fsp->fnum, (int)numtowrite, (int)nwritten ) );

	if (write_through && tcount==nwritten) {
		/* We need to send both a primary and a secondary response */
		smb_setlen(outbuf,outsize - 4);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_writebmpx: send_smb failed.");

		/* Now the secondary */
		outsize = set_message(outbuf,1,0,True);
		SCVAL(outbuf,smb_com,SMBwritec);
		SSVAL(outbuf,smb_vwv0,nwritten);
	}

	END_PROFILE(SMBwriteBmpx);
	return(outsize);
}

/****************************************************************************
 Reply to a SMBwritebs (write block multiplex secondary) request.
****************************************************************************/

int reply_writebs(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t tcount;
	BOOL write_through;
	int smb_doff;
	char *data;
	write_bmpx_struct *wbms;
	BOOL send_response = False; 
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteBs);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	tcount = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	numtowrite = SVAL(inbuf,smb_vwv6);
	smb_doff = SVAL(inbuf,smb_vwv7);

	data = smb_base(inbuf) + smb_doff;

	/* We need to send an SMBwriteC response, not an SMBwritebs */
	SCVAL(outbuf,smb_com,SMBwritec);

	/* This fd should have an auxiliary struct attached,
		check that it does */
	wbms = fsp->wbmpx_ptr;
	if(!wbms) {
		END_PROFILE(SMBwriteBs);
		return(-1);
	}

	/* If write through is set we can return errors, else we must cache them */
	write_through = wbms->wr_mode;

	/* Check for an earlier error */
	if(wbms->wr_discard) {
		END_PROFILE(SMBwriteBs);
		return -1; /* Just discard the packet */
	}

	nwritten = write_file(fsp,data,startpos,numtowrite);

	if(lp_syncalways(SNUM(conn)) || write_through)
		sync_file(conn,fsp);
  
	if (nwritten < (ssize_t)numtowrite) {
		if(write_through) {
			/* We are returning an error - we can delete the aux struct */
			if (wbms)
				free((char *)wbms);
			fsp->wbmpx_ptr = NULL;
			END_PROFILE(SMBwriteBs);
			return(ERROR_DOS(ERRHRD,ERRdiskfull));
		}
		END_PROFILE(SMBwriteBs);
		return(CACHE_ERROR(wbms,ERRHRD,ERRdiskfull));
	}

	/* Increment the total written, if this matches tcount
		we can discard the auxiliary struct (hurrah !) and return a writeC */
	wbms->wr_total_written += nwritten;
	if(wbms->wr_total_written >= tcount) {
		if (write_through) {
			outsize = set_message(outbuf,1,0,True);
			SSVAL(outbuf,smb_vwv0,wbms->wr_total_written);    
			send_response = True;
		}

		free((char *)wbms);
		fsp->wbmpx_ptr = NULL;
	}

	if(send_response) {
		END_PROFILE(SMBwriteBs);
		return(outsize);
	}

	END_PROFILE(SMBwriteBs);
	return(-1);
}

/****************************************************************************
 Reply to a SMBgetattrE.
****************************************************************************/

int reply_getattrE(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	SMB_STRUCT_STAT sbuf;
	int outsize = 0;
	int mode;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBgetattrE);

	outsize = set_message(outbuf,11,0,True);

	if(!fsp || (fsp->conn != conn)) {
		END_PROFILE(SMBgetattrE);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	/* Do an fstat on this file */
	if(fsp_stat(fsp, &sbuf)) {
		END_PROFILE(SMBgetattrE);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}
  
	mode = dos_mode(conn,fsp->fsp_name,&sbuf);
  
	/*
	 * Convert the times into dos times. Set create
	 * date to be last modify date as UNIX doesn't save
	 * this.
	 */

	put_dos_date2(outbuf,smb_vwv0,get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn))));
	put_dos_date2(outbuf,smb_vwv2,sbuf.st_atime);
	put_dos_date2(outbuf,smb_vwv4,sbuf.st_mtime);

	if (mode & aDIR) {
		SIVAL(outbuf,smb_vwv6,0);
		SIVAL(outbuf,smb_vwv8,0);
	} else {
		uint32 allocation_size = get_allocation_size(fsp, &sbuf);
		SIVAL(outbuf,smb_vwv6,(uint32)sbuf.st_size);
		SIVAL(outbuf,smb_vwv8,allocation_size);
	}
	SSVAL(outbuf,smb_vwv10, mode);
  
	DEBUG( 3, ( "reply_getattrE fnum=%d\n", fsp->fnum));
  
	END_PROFILE(SMBgetattrE);
	return(outsize);
}
