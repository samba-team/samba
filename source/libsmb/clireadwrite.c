/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client file read/write routines
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
size_t cli_read_one(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size)
{
	char *p;
	int size2;

	if (size == 0) return 0;

	if (buf == NULL)
	{
		DEBUG(1, ("cli_read_one: NULL buf\n"));
		return 0;
	}

	cli_issue_read(cli, fnum, offset, size, 0);

	if (!cli_receive_smb(cli))
	{
		return -1;
	}

	size2 = SVAL(cli->inbuf, smb_vwv5);

	if (cli_error(cli, NULL, NULL))
	{
		return -1;
	}

	if (size2 > size)
	{
		DEBUG(0,("server returned more than we wanted!\n"));
		exit(1);
	}

	p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);
	memcpy(buf, p, size2);

	return size2;
}

/****************************************************************************
  read from a file
****************************************************************************/
size_t cli_read(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size, BOOL overlap)
{
	char *p;
	int total = -1;
	int issued=0;
	int received=0;
	int mpx = overlap ? MIN(MAX(cli->max_mux-1, 1), MAX_MAX_MUX_LIMIT) : 1;
	int block = (cli->max_xmit - (smb_size+32)) & ~2047;
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

		if (cli_error(cli, NULL, NULL))
		{
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
			exit(1);
		}
		if (mid >= issued) {
			DEBUG(0,("invalid mid from server!\n"));
			exit(1);
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
			    size_t size, size_t bytes_left, int i)
{
	char *p;

	if (cli->outbuf == NULL || cli->inbuf == NULL)
	{
		DEBUG(1, ("cli_issue_write: cli->(in|out)buf is NULL\n"));
		/* XXX how to indicate a failure? */
		return;
	}

	memset(cli->outbuf, 0, smb_size);
	memset(cli->inbuf, 0, smb_size);

	set_message(cli->outbuf,12,size,True);
	
	CVAL(cli->outbuf,smb_com) = SMBwriteX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);

	SIVAL(cli->outbuf,smb_vwv3,offset);
	SIVAL(cli->outbuf,smb_vwv5,IS_BITS_SET_SOME(mode, 0x000C) ? 0xFFFFFFFF : 0);
	SSVAL(cli->outbuf,smb_vwv7,mode);

	SSVAL(cli->outbuf,smb_vwv8,IS_BITS_SET_SOME(mode, 0x000C) ? bytes_left : 0);
	SSVAL(cli->outbuf,smb_vwv10,size);
	SSVAL(cli->outbuf,smb_vwv11,
	      smb_buf(cli->outbuf) - smb_base(cli->outbuf));
	
	p = smb_base(cli->outbuf) + SVAL(cli->outbuf,smb_vwv11);
	memcpy(p, buf, size);

	SSVAL(cli->outbuf,smb_mid,cli->mid + i);
	
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
		  char *buf, off_t offset, size_t size, size_t bytes_left)
{
	int total = -1;
	int issued = 0;
	int received = 0;
	int mpx = MAX(cli->max_mux-1, 1);
	int block = (cli->max_xmit - (smb_size+32)) & ~1023;
	int mid;
	int blocks = (size + (block-1)) / block;

	if (size == 0) return 0;

	while (received < blocks) {
		int size2;

		while (issued - received < mpx && issued < blocks)
		{
			int size1 = MIN(block, size-issued*block);
			cli_issue_write(cli, fnum, offset+issued*block,
			                write_mode,
			                buf + issued*block,
					size1, bytes_left, issued);
			issued++;
			bytes_left -= size1;
		}

		if (!cli_receive_smb(cli))
		{
			return total;
		}

		received++;
		mid = SVAL(cli->inbuf, smb_mid) - cli->mid;
		size2 = SVAL(cli->inbuf, smb_vwv2);

		if (CVAL(cli->inbuf,smb_rcls) != 0)
		{
			blocks = MIN(blocks, mid-1);
			continue;
		}

		if (size2 <= 0) {
			blocks = MIN(blocks, mid-1);
			/* this distinguishes EOF from an error */
			total = MAX(total, 0);
			continue;
		}

		total += size2;

		total = MAX(total, mid*block + size2);
	}

	while (received < issued)
	{
		cli_receive_smb(cli);
		received++;
	}
	
	return total;
}

