/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   error packet handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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

extern int DEBUGLEVEL;
extern uint32 global_client_caps;

/* these can be set by some functions to override the error codes */
int unix_ERR_class=SMB_SUCCESS;
int unix_ERR_code=0;

struct {
	int unixerror;
	int smbclass;
	int smbcode;
} unix_smb_errmap[] = {
	{EPERM,ERRDOS,ERRnoaccess},
	{EACCES,ERRDOS,ERRnoaccess},
	{ENOENT,ERRDOS,ERRbadfile},
	{ENOTDIR,ERRDOS,ERRbadpath},
	{EIO,ERRHRD,ERRgeneral},
	{EBADF,ERRDOS,ERRbadfid},
	{EINVAL,ERRSRV,ERRsrverror},
	{EEXIST,ERRDOS,ERRfilexists},
	{ENFILE,ERRDOS,ERRnofids},
	{EMFILE,ERRDOS,ERRnofids},
	{ENOSPC,ERRHRD,ERRdiskfull},
#ifdef EDQUOT
	{EDQUOT,ERRHRD,ERRdiskfull},
#endif
#ifdef ENOTEMPTY
	{ENOTEMPTY,ERRDOS,ERRnoaccess},
#endif
#ifdef EXDEV
	{EXDEV,ERRDOS,ERRdiffdevice},
#endif
	{EROFS,ERRHRD,ERRnowrite},
	{0,0,0}
};

/****************************************************************************
 Create an error packet from errno.
****************************************************************************/

int unix_error_packet(char *outbuf,int def_class,uint32 def_code,int line)
{
	int eclass=def_class;
	int ecode=def_code;
	int i=0;

	if (unix_ERR_class != SMB_SUCCESS) {
		eclass = unix_ERR_class;
		ecode = unix_ERR_code;
		unix_ERR_class = SMB_SUCCESS;
		unix_ERR_code = 0;
	} else {
		while (unix_smb_errmap[i].smbclass != 0) {
			if (unix_smb_errmap[i].unixerror == errno) {
				eclass = unix_smb_errmap[i].smbclass;
				ecode = unix_smb_errmap[i].smbcode;
				break;
			}
			i++;
		}
	}

	return(error_packet(outbuf,0,eclass,ecode,line));
}

/****************************************************************************
 Create an error packet. Normally called using the ERROR() macro.
****************************************************************************/

int error_packet(char *outbuf,uint32 nt_err, int error_class,uint32 error_code,int line)
{
	int outsize = set_message(outbuf,0,0,True);
	int cmd = CVAL(outbuf,smb_com);

	if (errno != 0)
		DEBUG(3,("error string = %s\n",strerror(errno)));
  
	if ((global_client_caps & CAP_STATUS32) && (nt_err != 0)) {
		SSVAL(outbuf, smb_flg2, SVAL(outbuf, smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
		SIVAL(outbuf,smb_rcls,nt_err);
    
		DEBUG( 3, ( "32 bit error packet at line %d cmd=%d (%s) eclass=%08x [%s]\n",
			line, cmd, smb_fn_name(cmd), nt_err, smb_errstr(outbuf) ) );

	} else {
		CVAL(outbuf,smb_rcls) = error_class;
		SSVAL(outbuf,smb_err,error_code);  
		DEBUG( 3, ( "error packet at line %d cmd=%d (%s) eclass=%d ecode=%d\n",
				line, cmd, smb_fn_name(cmd), error_class, error_code ) );
	}
  
	return(outsize);
}
