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

/* these can be set by some functions to override the error codes */
int unix_ERR_class=SMB_SUCCESS;
int unix_ERR_code=0;
NTSTATUS unix_ERR_ntstatus = NT_STATUS_OK;

/* From lib/error.c */
extern struct unix_error_map unix_dos_nt_errmap[];

/****************************************************************************
 Create an error packet from a cached error.
****************************************************************************/
 
int cached_error_packet(char *outbuf,files_struct *fsp,int line,const char *file)
{
	write_bmpx_struct *wbmpx = fsp->wbmpx_ptr;
 
	int32 eclass = wbmpx->wr_errclass;
	int32 err = wbmpx->wr_error;
 
	/* We can now delete the auxiliary struct */
	SAFE_FREE(wbmpx);
	return error_packet(outbuf,NT_STATUS_OK,eclass,err,line,file);
}

/****************************************************************************
 Create an error packet from errno.
****************************************************************************/

int unix_error_packet(char *outbuf,int def_class,uint32 def_code,
		      int line, const char *file)
{
	int eclass=def_class;
	int ecode=def_code;
	NTSTATUS ntstatus = NT_STATUS_OK;
	int i=0;

	if (unix_ERR_class != SMB_SUCCESS) {
		eclass = unix_ERR_class;
		ecode = unix_ERR_code;
		ntstatus = unix_ERR_ntstatus;
		unix_ERR_class = SMB_SUCCESS;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
	} else {
		while (unix_dos_nt_errmap[i].dos_class != 0) {
			if (unix_dos_nt_errmap[i].unix_error == errno) {
				eclass = unix_dos_nt_errmap[i].dos_class;
				ecode = unix_dos_nt_errmap[i].dos_code;
				ntstatus = unix_dos_nt_errmap[i].nt_error;
				break;
			}
			i++;
		}
	}

	return error_packet(outbuf,ntstatus,eclass,ecode,line,file);
}


/****************************************************************************
 Create an error packet. Normally called using the ERROR() macro.
****************************************************************************/

int error_packet(char *outbuf,NTSTATUS ntstatus,
		 uint8 eclass,uint32 ecode,int line, const char *file)
{
	int outsize = set_message(outbuf,0,0,True);
	extern uint32 global_client_caps;

	if (errno != 0)
		DEBUG(3,("error string = %s\n",strerror(errno)));
  
	/*
	 * We can explicitly force 32 bit error codes even when the
	 * parameter "nt status" is set to no by pre-setting the
	 * FLAGS2_32_BIT_ERROR_CODES bit in the smb_flg2 outbuf.
	 * This is to allow work arounds for client bugs that are needed
	 * when talking with clients that normally expect nt status codes. JRA.
	 */

	if ((lp_nt_status_support() || (SVAL(outbuf,smb_flg2) & FLAGS2_32_BIT_ERROR_CODES)) && (global_client_caps & CAP_STATUS32)) {
		if (NT_STATUS_V(ntstatus) == 0 && eclass)
			ntstatus = dos_to_ntstatus(eclass, ecode);
		SIVAL(outbuf,smb_rcls,NT_STATUS_V(ntstatus));
		SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2)|FLAGS2_32_BIT_ERROR_CODES);
		DEBUG(3,("error packet at %s(%d) cmd=%d (%s) %s\n",
			 file, line,
			 (int)CVAL(outbuf,smb_com),
			 smb_fn_name(CVAL(outbuf,smb_com)),
			 get_nt_error_msg(ntstatus)));
		return outsize;
	} 

	if (eclass == 0 && NT_STATUS_V(ntstatus))
		ntstatus_to_dos(ntstatus, &eclass, &ecode);

	SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2)&~FLAGS2_32_BIT_ERROR_CODES);
	SSVAL(outbuf,smb_rcls,eclass);
	SSVAL(outbuf,smb_err,ecode);  

	DEBUG(3,("error packet at %s(%d) cmd=%d (%s) eclass=%d ecode=%d\n",
		  file, line,
		  (int)CVAL(outbuf,smb_com),
		  smb_fn_name(CVAL(outbuf,smb_com)),
		  eclass,
		  ecode));

	return outsize;
}
