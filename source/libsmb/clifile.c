/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   
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
 Hard/Symlink a file (UNIX extensions).
****************************************************************************/

static BOOL cli_link_internal(struct cli_state *cli, const char *fname_src, const char *fname_dst, BOOL hard_link)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_SETPATHINFO;
	char param[sizeof(pstring)+6];
	pstring data;
	char *rparam=NULL, *rdata=NULL;
	char *p;

	memset(param, 0, sizeof(param));
	SSVAL(param,0,hard_link ? SMB_SET_FILE_UNIX_HLINK : SMB_SET_FILE_UNIX_LINK);
	p = &param[6];

	p += clistr_push(cli, p, fname_src, -1, STR_TERMINATE|STR_CONVERT);
	param_len = PTR_DIFF(p, param);

	p = data;
	p += clistr_push(cli, p, fname_dst, -1, STR_TERMINATE|STR_CONVERT);
	data_len = PTR_DIFF(p, data);

	if (!cli_send_trans(cli, SMBtrans2,
		NULL,                        /* name */
		-1, 0,                          /* fid, flags */
		&setup, 1, 0,                   /* setup, length, max */
		param, param_len, 2,            /* param, length, max */
		(char *)&data,  data_len, cli->max_xmit /* data, length, max */
		)) {
			return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
		&rparam, &param_len,
		&rdata, &data_len)) {
			return False;
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/

uint32  unix_perms_to_wire(mode_t perms)
{
        uint32 ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/****************************************************************************
 Symlink a file (UNIX extensions).
****************************************************************************/

BOOL cli_unix_symlink(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	return cli_link_internal(cli, fname_src, fname_dst, False);
}

/****************************************************************************
 Hard a file (UNIX extensions).
****************************************************************************/

BOOL cli_unix_hardlink(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	return cli_link_internal(cli, fname_src, fname_dst, True);
}

/****************************************************************************
 Chmod or chown a file internal (UNIX extensions).
****************************************************************************/

static BOOL cli_unix_chmod_chown_internal(struct cli_state *cli, const char *fname, uint32 mode, uint32 uid, uint32 gid)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_SETPATHINFO;
	char param[sizeof(pstring)+6];
	char data[100];
	char *rparam=NULL, *rdata=NULL;
	char *p;

	memset(param, 0, sizeof(param));
	memset(data, 0, sizeof(data));
	SSVAL(param,0,SMB_SET_FILE_UNIX_BASIC);
	p = &param[6];

	p += clistr_push(cli, p, fname, -1, STR_TERMINATE|STR_CONVERT);
	param_len = PTR_DIFF(p, param);

	SIVAL(data,40,uid);
	SIVAL(data,48,gid);
	SIVAL(data,84,mode);

	data_len = 100;

	if (!cli_send_trans(cli, SMBtrans2,
		NULL,                        /* name */
		-1, 0,                          /* fid, flags */
		&setup, 1, 0,                   /* setup, length, max */
		param, param_len, 2,            /* param, length, max */
		(char *)&data,  data_len, cli->max_xmit /* data, length, max */
		)) {
			return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
		&rparam, &param_len,
		&rdata, &data_len)) {
			return False;
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/****************************************************************************
 chmod a file (UNIX extensions).
****************************************************************************/

BOOL cli_unix_chmod(struct cli_state *cli, const char *fname, mode_t mode)
{
	return cli_unix_chmod_chown_internal(cli, fname, 
		unix_perms_to_wire(mode), SMB_UID_NO_CHANGE, SMB_GID_NO_CHANGE);
}

/****************************************************************************
 chown a file (UNIX extensions).
****************************************************************************/

BOOL cli_unix_chown(struct cli_state *cli, const char *fname, uid_t uid, gid_t gid)
{
	return cli_unix_chmod_chown_internal(cli, fname, SMB_MODE_NO_CHANGE, (uint32)uid, (uint32)gid);
}

/****************************************************************************
 Rename a file.
****************************************************************************/

BOOL cli_rename(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,1, 0, True);

	SCVAL(cli->outbuf,smb_com,SMBmv);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN | aDIR);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, fname_src, -1, STR_TERMINATE|STR_CONVERT);
	*p++ = 4;
	p += clistr_push(cli, p, fname_dst, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli))
		return False;

	if (cli_is_error(cli))
		return False;

	return True;
}

/****************************************************************************
 Delete a file.
****************************************************************************/

BOOL cli_unlink(struct cli_state *cli, const char *fname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,1, 0,True);

	SCVAL(cli->outbuf,smb_com,SMBunlink);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN);
  
	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	p += clistr_push(cli, p, fname, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);
	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Create a directory.
****************************************************************************/

BOOL cli_mkdir(struct cli_state *cli, const char *dname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0, 0,True);

	SCVAL(cli->outbuf,smb_com,SMBmkdir);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	p += clistr_push(cli, p, dname, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Remove a directory.
****************************************************************************/

BOOL cli_rmdir(struct cli_state *cli, const char *dname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0, 0, True);

	SCVAL(cli->outbuf,smb_com,SMBrmdir);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	p += clistr_push(cli, p, dname, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Set or clear the delete on close flag.
****************************************************************************/

int cli_nt_delete_on_close(struct cli_state *cli, int fnum, BOOL flag)
{
	unsigned int data_len = 1;
	unsigned int param_len = 6;
	uint16 setup = TRANSACT2_SETFILEINFO;
	pstring param;
	unsigned char data;
	char *rparam=NULL, *rdata=NULL;

	memset(param, 0, param_len);
	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_SET_FILE_DISPOSITION_INFO);

	data = flag ? 1 : 0;

	if (!cli_send_trans(cli, SMBtrans2,
		NULL,                        /* name */
		-1, 0,                          /* fid, flags */
		&setup, 1, 0,                   /* setup, length, max */
		param, param_len, 2,            /* param, length, max */
		(char *)&data,  data_len, cli->max_xmit /* data, length, max */
		)) {
			return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
		&rparam, &param_len,
		&rdata, &data_len)) {
			return False;
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/****************************************************************************
 Open a file - exposing the full horror of the NT API :-).
 Used in smbtorture.
****************************************************************************/

int cli_nt_create_full(struct cli_state *cli, const char *fname, uint32 DesiredAccess,
		 uint32 FileAttributes, uint32 ShareAccess,
		 uint32 CreateDisposition, uint32 CreateOptions)
{
	char *p;
	int len;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,24,0,True);

	SCVAL(cli->outbuf,smb_com,SMBntcreateX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	if (cli->use_oplocks)
		SIVAL(cli->outbuf,smb_ntcreate_Flags, REQUEST_OPLOCK|REQUEST_BATCH_OPLOCK);
	else
		SIVAL(cli->outbuf,smb_ntcreate_Flags, 0);
	SIVAL(cli->outbuf,smb_ntcreate_RootDirectoryFid, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_DesiredAccess, DesiredAccess);
	SIVAL(cli->outbuf,smb_ntcreate_FileAttributes, FileAttributes);
	SIVAL(cli->outbuf,smb_ntcreate_ShareAccess, ShareAccess);
	SIVAL(cli->outbuf,smb_ntcreate_CreateDisposition, CreateDisposition);
	SIVAL(cli->outbuf,smb_ntcreate_CreateOptions, CreateOptions);
	SIVAL(cli->outbuf,smb_ntcreate_ImpersonationLevel, 0x02);

	p = smb_buf(cli->outbuf);
	/* this alignment and termination is critical for netapp filers. Don't change */
	p += clistr_align_out(cli, p, 0);
	len = clistr_push(cli, p, fname, -1, 0);
	p += len;
	SSVAL(cli->outbuf,smb_ntcreate_NameLength, len);
	/* sigh. this copes with broken netapp filer behaviour */
	p += clistr_push(cli, p, "", -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (cli_is_error(cli)) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2 + 1);
}

/****************************************************************************
 Open a file.
****************************************************************************/

int cli_nt_create(struct cli_state *cli, const char *fname, uint32 DesiredAccess)
{
	return cli_nt_create_full(cli, fname, DesiredAccess, 0,
				FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_EXISTS_OPEN, 0x0);
}

/****************************************************************************
 Open a file
 WARNING: if you open with O_WRONLY then getattrE won't work!
****************************************************************************/

int cli_open(struct cli_state *cli, const char *fname, int flags, int share_mode)
{
	char *p;
	unsigned openfn=0;
	unsigned accessmode=0;

	if (flags & O_CREAT)
		openfn |= (1<<4);
	if (!(flags & O_EXCL)) {
		if (flags & O_TRUNC)
			openfn |= (1<<1);
		else
			openfn |= (1<<0);
	}

	accessmode = (share_mode<<4);

	if ((flags & O_ACCMODE) == O_RDWR) {
		accessmode |= 2;
	} else if ((flags & O_ACCMODE) == O_WRONLY) {
		accessmode |= 1;
	} 

#if defined(O_SYNC)
	if ((flags & O_SYNC) == O_SYNC) {
		accessmode |= (1<<14);
	}
#endif /* O_SYNC */

	if (share_mode == DENY_FCB) {
		accessmode = 0xFF;
	}

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,15,0,True);

	SCVAL(cli->outbuf,smb_com,SMBopenX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,0);  /* no additional info */
	SSVAL(cli->outbuf,smb_vwv3,accessmode);
	SSVAL(cli->outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
	SSVAL(cli->outbuf,smb_vwv5,0);
	SSVAL(cli->outbuf,smb_vwv8,openfn);

	if (cli->use_oplocks) {
		/* if using oplocks then ask for a batch oplock via
                   core and extended methods */
		SCVAL(cli->outbuf,smb_flg, CVAL(cli->outbuf,smb_flg)|
			FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK);
		SSVAL(cli->outbuf,smb_vwv2,SVAL(cli->outbuf,smb_vwv2) | 6);
	}
  
	p = smb_buf(cli->outbuf);
	p += clistr_push(cli, p, fname, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (cli_is_error(cli)) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2);
}

/****************************************************************************
 Close a file.
****************************************************************************/

BOOL cli_close(struct cli_state *cli, int fnum)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,3,0,True);

	SCVAL(cli->outbuf,smb_com,SMBclose);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	return !cli_is_error(cli);
}

/****************************************************************************
 send a lock with a specified locktype
 this is used for testing LOCKING_ANDX_CANCEL_LOCK
****************************************************************************/
NTSTATUS cli_locktype(struct cli_state *cli, int fnum,
		      uint32 offset, uint32 len, int timeout, unsigned char locktype)
{
	char *p;
	int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,locktype);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	p += 10;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);

	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);
	}

	if (!cli_receive_smb(cli)) {
		cli->timeout = saved_timeout;
		return NT_STATUS_UNSUCCESSFUL;
	}

	cli->timeout = saved_timeout;

	return cli_nt_error(cli);
}

/****************************************************************************
 Lock a file.
****************************************************************************/

BOOL cli_lock(struct cli_state *cli, int fnum, 
	      uint32 offset, uint32 len, int timeout, enum brl_type lock_type)
{
	char *p;
	int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,(lock_type == READ_LOCK? 1 : 0));
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	p += 10;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);

	cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);
	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);
	}

	if (!cli_receive_smb(cli)) {
		cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Unlock a file.
****************************************************************************/

BOOL cli_unlock(struct cli_state *cli, int fnum, uint32 offset, uint32 len)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,0);
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);
	p += 10;
	cli_setup_bcc(cli, p);
	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Lock a file with 64 bit offsets.
****************************************************************************/

BOOL cli_lock64(struct cli_state *cli, int fnum, 
		SMB_BIG_UINT offset, SMB_BIG_UINT len, int timeout, enum brl_type lock_type)
{
	char *p;
        int saved_timeout = cli->timeout;
	int ltype;

	if (! (cli->capabilities & CAP_LARGE_FILES)) {
		return cli_lock(cli, fnum, offset, len, timeout, lock_type);
	}

	ltype = (lock_type == READ_LOCK? 1 : 0);
	ltype |= LOCKING_ANDX_LARGE_FILES;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,ltype);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SIVAL(p, 0, cli->pid);
	SOFF_T_R(p, 4, offset);
	SOFF_T_R(p, 12, len);
	p += 20;

	cli_setup_bcc(cli, p);
	cli_send_smb(cli);

        cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);

	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 5*1000);
	}

	if (!cli_receive_smb(cli)) {
                cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Unlock a file with 64 bit offsets.
****************************************************************************/

BOOL cli_unlock64(struct cli_state *cli, int fnum, SMB_BIG_UINT offset, SMB_BIG_UINT len)
{
	char *p;

	if (! (cli->capabilities & CAP_LARGE_FILES)) {
		return cli_unlock(cli, fnum, offset, len);
	}

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,LOCKING_ANDX_LARGE_FILES);
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SIVAL(p, 0, cli->pid);
	SOFF_T_R(p, 4, offset);
	SOFF_T_R(p, 12, len);
	p += 20;
	cli_setup_bcc(cli, p);
	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Do a SMBgetattrE call. The size is 32 bits.
****************************************************************************/

BOOL cli_getattrE(struct cli_state *cli, int fd, 
		  uint16 *attr, SMB_BIG_UINT *size, 
		  time_t *c_time, time_t *a_time, time_t *m_time)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,1,0,True);

	SCVAL(cli->outbuf,smb_com,SMBgetattrE);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fd);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (cli_is_error(cli)) {
		return False;
	}

	if (size) {
		*size = IVAL(cli->inbuf, smb_vwv6);
	}

	if (attr) {
		*attr = SVAL(cli->inbuf,smb_vwv10);
	}

	if (c_time) {
		*c_time = make_unix_date3(cli->inbuf+smb_vwv0);
	}

	if (a_time) {
		*a_time = make_unix_date3(cli->inbuf+smb_vwv2);
	}

	if (m_time) {
		*m_time = make_unix_date3(cli->inbuf+smb_vwv4);
	}

	return True;
}

/****************************************************************************
 Do a SMBgetatr call
****************************************************************************/

BOOL cli_getatr(struct cli_state *cli, const char *fname, 
		uint16 *attr, size_t *size, time_t *t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0,0,True);

	SCVAL(cli->outbuf,smb_com,SMBgetatr);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, fname, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (cli_is_error(cli)) {
		return False;
	}

	if (size) {
		*size = IVAL(cli->inbuf, smb_vwv3);
	}

	if (t) {
		*t = make_unix_date3(cli->inbuf+smb_vwv1);
	}

	if (attr) {
		*attr = SVAL(cli->inbuf,smb_vwv0);
	}


	return True;
}

/****************************************************************************
 Do a SMBsetatr call.
****************************************************************************/

BOOL cli_setatr(struct cli_state *cli, const char *fname, uint16 attr, time_t t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBsetatr);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0, attr);
	put_dos_date3(cli->outbuf,smb_vwv1, t);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, fname, -1, STR_TERMINATE|STR_CONVERT);
	*p++ = 4;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Check for existance of a dir.
****************************************************************************/

BOOL cli_chkpath(struct cli_state *cli, const char *path)
{
	pstring path2;
	char *p;
	
	safe_strcpy(path2,path,sizeof(pstring));
	trim_string(path2,NULL,"\\");
	if (!*path2) *path2 = '\\';
	
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	SCVAL(cli->outbuf,smb_com,SMBchkpth);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, path2, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) return False;

	return True;
}

/****************************************************************************
 Query disk space.
****************************************************************************/

BOOL cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail)
{
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	SCVAL(cli->outbuf,smb_com,SMBdskattr);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	*bsize = SVAL(cli->inbuf,smb_vwv1)*SVAL(cli->inbuf,smb_vwv2);
	*total = SVAL(cli->inbuf,smb_vwv0);
	*avail = SVAL(cli->inbuf,smb_vwv3);
	
	return True;
}

/****************************************************************************
 Create and open a temporary file.
****************************************************************************/

int cli_ctemp(struct cli_state *cli, const char *path, char **tmp_path)
{
	int len;
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,3,0,True);

	SCVAL(cli->outbuf,smb_com,SMBctemp);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, path, -1, STR_TERMINATE|STR_CONVERT);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (cli_is_error(cli)) {
		return -1;
	}

	/* despite the spec, the result has a -1, followed by
	   length, followed by name */
	p = smb_buf(cli->inbuf);
	p += 4;
	len = smb_buflen(cli->inbuf) - 4;
	if (len <= 0) return -1;

	if (tmp_path) {
		pstring path2;
		clistr_pull(cli, path2, p, 
			    sizeof(path2), len, STR_ASCII);
		*tmp_path = strdup(path2);
	}

	return SVAL(cli->inbuf,smb_vwv0);
}
