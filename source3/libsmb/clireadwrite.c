/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client file read/write routines
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
issue a single SMBread and don't wait for a reply
****************************************************************************/
static void cli_issue_read(struct cli_state *cli, int fnum, off_t offset, 
			   size_t size, int i)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,10,0,True);
		
	CVAL(cli->outbuf,smb_com) = SMBreadX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);
	SSVAL(cli->outbuf,smb_vwv5,size);
	SSVAL(cli->outbuf,smb_vwv6,size);
	SSVAL(cli->outbuf,smb_mid,cli->mid + i);

	cli_send_smb(cli);
}

/****************************************************************************
  read from a file
****************************************************************************/
size_t cli_read(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size)
{
	char *p;
	int total = -1;
	int issued=0;
	int received=0;
/*
 * There is a problem in this code when mpx is more than one.
 * for some reason files can get corrupted when being read.
 * Until we understand this fully I am serializing reads (one
 * read/one reply) for now. JRA.
 */
#if 0
	int mpx = MAX(cli->max_mux-1, 1); 
#else
	int mpx = 1;
#endif
	int block = (cli->max_xmit - (smb_size+32)) & ~1023;
	int mid;
	int blocks = (size + (block-1)) / block;

	if (size == 0) return 0;

	while (received < blocks) {
		int size2;

		while (issued - received < mpx && issued < blocks) {
			int size1 = MIN(block, size-issued*block);
			cli_issue_read(cli, fnum, offset+issued*block, size1, issued);
			issued++;
		}

		if (!cli_receive_smb(cli)) {
			return total;
		}

		received++;
		mid = SVAL(cli->inbuf, smb_mid) - cli->mid;
		size2 = SVAL(cli->inbuf, smb_vwv5);

		if (CVAL(cli->inbuf,smb_rcls) != 0) {
			blocks = MIN(blocks, mid-1);
			continue;
		}

		if (size2 <= 0) {
			blocks = MIN(blocks, mid-1);
			/* this distinguishes EOF from an error */
			total = MAX(total, 0);
			continue;
		}

		if (size2 > block) {
			DEBUG(0,("server returned more than we wanted!\n"));
			return -1;
		}
		if (mid >= issued) {
			DEBUG(0,("invalid mid from server!\n"));
			return -1;
		}
		p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);

		memcpy(buf+mid*block, p, size2);

		total = MAX(total, mid*block + size2);
	}

	while (received < issued) {
		cli_receive_smb(cli);
		received++;
	}
	
	return total;
}


/****************************************************************************
issue a single SMBwrite and don't wait for a reply
****************************************************************************/
static void cli_issue_write(struct cli_state *cli, int fnum, off_t offset, uint16 mode, char *buf,
			    size_t size, int i)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,12,size,True);
	
	CVAL(cli->outbuf,smb_com) = SMBwriteX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);

	SIVAL(cli->outbuf,smb_vwv3,offset);
	SIVAL(cli->outbuf,smb_vwv5,IS_BITS_SET_ALL(mode, 0x0008) ? 0xFFFFFFFF : 0);
	SSVAL(cli->outbuf,smb_vwv7,mode);

	SSVAL(cli->outbuf,smb_vwv8,IS_BITS_SET_ALL(mode, 0x0008) ? size : 0);
	SSVAL(cli->outbuf,smb_vwv10,size);
	SSVAL(cli->outbuf,smb_vwv11,
	      smb_buf(cli->outbuf) - smb_base(cli->outbuf));
	
	p = smb_base(cli->outbuf) + SVAL(cli->outbuf,smb_vwv11);
	memcpy(p, buf, size);

	SSVAL(cli->outbuf,smb_mid,cli->mid + i);
	
	show_msg(cli->outbuf);
	cli_send_smb(cli);
}

/****************************************************************************
  write to a file
  write_mode: 0x0001 disallow write cacheing
              0x0002 return bytes remaining
              0x0004 use raw named pipe protocol
              0x0008 start of message mode named pipe protocol
****************************************************************************/
ssize_t cli_write(struct cli_state *cli,
		  int fnum, uint16 write_mode,
		  char *buf, off_t offset, size_t size)
{
	int bwritten = 0;
	int issued = 0;
	int received = 0;
	int mpx = MAX(cli->max_mux-1, 1);
	int block = (cli->max_xmit - (smb_size+32)) & ~1023;
	int blocks = (size + (block-1)) / block;

	while (received < blocks) {

		while ((issued - received < mpx) && (issued < blocks))
		{
			int bsent = issued * block;
			int size1 = MIN(block, size - bsent);

			cli_issue_write(cli, fnum, offset + bsent,
			                write_mode,
			                buf + bsent,
					size1, issued);
			issued++;
		}

		if (!cli_receive_smb(cli))
		{
			return bwritten;
		}

		received++;

		if (CVAL(cli->inbuf,smb_rcls) != 0)
		{
			break;
		}

		bwritten += SVAL(cli->inbuf, smb_vwv2);
	}

	while (received < issued && cli_receive_smb(cli))
	{
		received++;
	}
	
	return bwritten;
}


/****************************************************************************
  write to a file using a SMBwrite and not bypassing 0 byte writes
****************************************************************************/
ssize_t cli_smbwrite(struct cli_state *cli,
		     int fnum, char *buf, off_t offset, size_t size1)
{
	char *p;
	ssize_t total = 0;

	do {
		size_t size = MIN(size1, cli->max_xmit - 48);
		
		memset(cli->outbuf,'\0',smb_size);
		memset(cli->inbuf,'\0',smb_size);

		set_message(cli->outbuf,5, 3 + size,True);

		CVAL(cli->outbuf,smb_com) = SMBwrite;
		SSVAL(cli->outbuf,smb_tid,cli->cnum);
		cli_setup_packet(cli);
		
		SSVAL(cli->outbuf,smb_vwv0,fnum);
		SSVAL(cli->outbuf,smb_vwv1,size);
		SIVAL(cli->outbuf,smb_vwv2,offset);
		SSVAL(cli->outbuf,smb_vwv4,0);
		
		p = smb_buf(cli->outbuf);
		*p++ = 1;
		SSVAL(p, 0, size);
		memcpy(p+2, buf, size);
		
		cli_send_smb(cli);
		if (!cli_receive_smb(cli)) {
			return -1;
		}
		
		if (CVAL(cli->inbuf,smb_rcls) != 0) {
			return -1;
		}

		size = SVAL(cli->inbuf,smb_vwv0);
		if (size == 0) break;

		size1 -= size;
		total += size;
	} while (size1);

	return total;
}

