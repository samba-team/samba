/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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
rename a file
****************************************************************************/
BOOL cli_rename(struct cli_state *cli, char *fname_src, char *fname_dst)
{
        char *p;

        memset(cli->outbuf,'\0',smb_size);
        memset(cli->inbuf,'\0',smb_size);

        set_message(cli->outbuf,1, 4 + strlen(fname_src) + strlen(fname_dst), True);

        CVAL(cli->outbuf,smb_com) = SMBmv;
        SSVAL(cli->outbuf,smb_tid,cli->cnum);
        cli_setup_packet(cli);

        SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN | aDIR);

        p = smb_buf(cli->outbuf);
        *p++ = 4;
        pstrcpy(p,fname_src);
        unix_to_dos(p,True);
        p = skip_string(p,1);
        *p++ = 4;
        pstrcpy(p,fname_dst);
        unix_to_dos(p,True);

        cli_send_smb(cli);
        if (!cli_receive_smb(cli)) {
                return False;
        }

        if (CVAL(cli->inbuf,smb_rcls) != 0) {
                return False;
        }

        return True;
}

/****************************************************************************
delete a file
****************************************************************************/
BOOL cli_unlink(struct cli_state *cli, char *fname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,1, 2 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBunlink;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN);
  
	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,fname);
    unix_to_dos(p,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
create a directory
****************************************************************************/
BOOL cli_mkdir(struct cli_state *cli, char *dname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0, 2 + strlen(dname),True);

	CVAL(cli->outbuf,smb_com) = SMBmkdir;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,dname);
    unix_to_dos(p,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
remove a directory
****************************************************************************/
BOOL cli_rmdir(struct cli_state *cli, char *dname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0, 2 + strlen(dname),True);

	CVAL(cli->outbuf,smb_com) = SMBrmdir;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,dname);
    unix_to_dos(p,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}



/****************************************************************************
open a file
****************************************************************************/
int cli_nt_create(struct cli_state *cli, const char *fname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,24,1 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBntcreateX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SIVAL(cli->outbuf,smb_ntcreate_Flags, 0x06);
	SIVAL(cli->outbuf,smb_ntcreate_RootDirectoryFid, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_DesiredAccess, 0x2019f);
	SIVAL(cli->outbuf,smb_ntcreate_FileAttributes, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_ShareAccess, 0x03);
	SIVAL(cli->outbuf,smb_ntcreate_CreateDisposition, 0x01);
	SIVAL(cli->outbuf,smb_ntcreate_CreateOptions, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_ImpersonationLevel, 0x02);
	SSVAL(cli->outbuf,smb_ntcreate_NameLength, strlen(fname));

	p = smb_buf(cli->outbuf);
	pstrcpy(p,fname);
    unix_to_dos(p,True);
	p = skip_string(p,1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2 + 1);
}


/****************************************************************************
open a file
****************************************************************************/
int cli_open(struct cli_state *cli, const char *fname,
				int flags, int share_mode)
{
	char *p;
	unsigned openfn=0;
	unsigned accessmode=0;

	/* you must open for RW not just write - otherwise getattrE doesn't
	   work! */
	if ((flags & O_ACCMODE) == O_WRONLY && strncmp(cli->dev, "LPT", 3)) {
		flags = (flags & ~O_ACCMODE) | O_RDWR;
	}

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

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,15,1 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBopenX;
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
		CVAL(cli->outbuf,smb_flg) |= 
			FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK;
		SSVAL(cli->outbuf,smb_vwv2,SVAL(cli->outbuf,smb_vwv2) | 6);
	}
  
	p = smb_buf(cli->outbuf);
	pstrcpy(p,fname);
	unix_to_dos(p,True);
	p = skip_string(p,1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2);
}




/****************************************************************************
  close a file
****************************************************************************/
BOOL cli_close(struct cli_state *cli, int fnum)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,3,0,True);

	CVAL(cli->outbuf,smb_com) = SMBclose;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}


/****************************************************************************
  lock a file
****************************************************************************/
BOOL cli_lock(struct cli_state *cli, int fnum, 
	      uint32 offset, uint32 len, int timeout, enum brl_type lock_type)
{
	char *p;
        int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = (lock_type == READ_LOCK? 1 : 0);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);
	cli_send_smb(cli);

        cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);

	if (!cli_receive_smb(cli)) {
                cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
  unlock a file
****************************************************************************/
BOOL cli_unlock(struct cli_state *cli, int fnum, uint32 offset, uint32 len)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = 0;
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}





/****************************************************************************
do a SMBgetattrE call
****************************************************************************/
BOOL cli_getattrE(struct cli_state *cli, int fd, 
		  uint16 *attr, size_t *size, 
		  time_t *c_time, time_t *a_time, time_t *m_time)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,2,0,True);

	CVAL(cli->outbuf,smb_com) = SMBgetattrE;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fd);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
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
do a SMBgetatr call
****************************************************************************/
BOOL cli_getatr(struct cli_state *cli, char *fname, 
		uint16 *attr, size_t *size, time_t *t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0,strlen(fname)+2,True);

	CVAL(cli->outbuf,smb_com) = SMBgetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);
    unix_to_dos(p+1,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
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
do a SMBsetatr call
****************************************************************************/
BOOL cli_setatr(struct cli_state *cli, char *fname, uint16 attr, time_t t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,strlen(fname)+4,True);

	CVAL(cli->outbuf,smb_com) = SMBsetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0, attr);
	put_dos_date3(cli->outbuf,smb_vwv1, t);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);
    unix_to_dos(p+1,True);
	p = skip_string(p,1);
	*p = 4;

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}


/****************************************************************************
check for existance of a dir
****************************************************************************/
BOOL cli_chkpath(struct cli_state *cli, char *path)
{
	pstring path2;
	char *p;
	
	safe_strcpy(path2,path,sizeof(pstring));
	trim_string(path2,NULL,"\\");
	if (!*path2) *path2 = '\\';
	
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,4 + strlen(path2),True);
	SCVAL(cli->outbuf,smb_com,SMBchkpth);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	p = smb_buf(cli->outbuf);
	*p++ = 4;
	safe_strcpy(p,path2,strlen(path2));
	unix_to_dos(p,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_error(cli, NULL, NULL)) return False;

	return True;
}



/****************************************************************************
query disk space
****************************************************************************/
BOOL cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail)
{
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	CVAL(cli->outbuf,smb_com) = SMBdskattr;
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

