
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"


#define	PIPE		"\\PIPE\\"
#define	PIPELEN		strlen(PIPE)

extern int DEBUGLEVEL;
static int chain_pnum = -1;

#ifndef MAX_OPEN_PIPES
#define MAX_OPEN_PIPES 50
#endif

pipes_struct Pipes[MAX_OPEN_PIPES];

#define P_OPEN(p) ((p)->open)
#define P_OK(p,c) (P_OPEN(p) && (c)==((p)->conn))
#define VALID_PNUM(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PIPES))
#define OPEN_PNUM(pnum)    (VALID_PNUM(pnum) && P_OPEN(&(Pipes[pnum])))
#define PNUM_OK(pnum,c) (OPEN_PNUM(pnum) && (c)==Pipes[pnum].cnum)


/****************************************************************************
  reset pipe chain handle number
****************************************************************************/
void reset_chain_pnum(void)
{
	chain_pnum = -1;
}

/****************************************************************************
  sets chain pipe-file handle
****************************************************************************/
void set_chain_pnum(int new_pnum)
{
	chain_pnum = new_pnum;
}

/****************************************************************************
  initialise pipe handle states...
****************************************************************************/
void init_rpc_pipe_hnd(void)
{
	int i;
	/* we start at 1 here for an obscure reason I can't now remember,
	but I think is important :-) */
	for (i = 1; i < MAX_OPEN_PIPES; i++)
	{
		Pipes[i].open = False;
		Pipes[i].name[0] = 0;
		Pipes[i].pipe_srv_name[0] = 0;

		Pipes[i].rhdr.data  = NULL;
		Pipes[i].rdata.data = NULL;
		Pipes[i].rhdr.offset  = 0;
		Pipes[i].rdata.offset = 0;

		Pipes[i].file_offset     = 0;
		Pipes[i].hdr_offsets     = 0;
		Pipes[i].frag_len_left   = 0;
		Pipes[i].next_frag_start = 0;
	}

	return;
}

/****************************************************************************
  find first available file slot
****************************************************************************/
int open_rpc_pipe_hnd(char *pipe_name, connection_struct *conn, uint16 vuid)
{
	int i;
	/* we start at 1 here for an obscure reason I can't now remember,
	but I think is important :-) */
	for (i = 1; i < MAX_OPEN_PIPES; i++) {
		if (!Pipes[i].open) break;
	}

	if (i == MAX_OPEN_PIPES) {
		DEBUG(1,("ERROR! Out of pipe structures\n"));
		return(-1);
	}

	Pipes[i].open = True;
	Pipes[i].device_state = 0;
	Pipes[i].conn = conn;
	Pipes[i].uid  = vuid;
	
	Pipes[i].rhdr.data  = NULL;
	Pipes[i].rdata.data = NULL;
	Pipes[i].rhdr.offset  = 0;
	Pipes[i].rdata.offset = 0;
	
	Pipes[i].file_offset     = 0;
	Pipes[i].hdr_offsets     = 0;
	Pipes[i].frag_len_left   = 0;
	Pipes[i].next_frag_start = 0;
	
	fstrcpy(Pipes[i].name, pipe_name);
	
	DEBUG(4,("Opened pipe %s with handle %x\n",
		 pipe_name, i + PIPE_HANDLE_OFFSET));
	
	set_chain_pnum(i);
	
	return(i);
}

/****************************************************************************
 reads data from a pipe.

 headers are interspersed with the data at regular intervals.  by the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 calling create_rpc_request() here is a fudge.  the data should already
 have been prepared into arrays of headers + data stream sections.

 ****************************************************************************/
int read_pipe(uint16 pnum, char *data, uint32 pos, int n)
{
	pipes_struct *p = &Pipes[pnum - PIPE_HANDLE_OFFSET];
	DEBUG(6,("read_pipe: %x", pnum));

	if (VALID_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		DEBUG(6,("name: %s open: %s pos: %d len: %d",
		          p->name,
		          BOOLSTR(p->open),
		          pos, n));
	}

	if (OPEN_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		int num = 0;
		int len = 0;
		uint32 hdr_num = 0;
		int data_hdr_pos;
		int data_pos;

		DEBUG(6,("OK\n"));

		if (p->rhdr.data == NULL || p->rhdr.data->data == NULL ||
		    p->rhdr.data->data_used == 0)
		{
			return 0;
		}

		DEBUG(6,("read_pipe: p: %p file_offset: %d file_pos: %d\n",
		          p, p->file_offset, n));
		DEBUG(6,("read_pipe: frag_len_left: %d next_frag_start: %d\n",
		          p->frag_len_left, p->next_frag_start));

		/* the read request starts from where the SMBtrans2 left off. */
		data_pos     = p->file_offset - p->hdr_offsets;
		data_hdr_pos = p->file_offset;

		len = mem_buf_len(p->rhdr.data);
		num = len - (int)data_pos;

		DEBUG(6,("read_pipe: len: %d num: %d n: %d\n", len, num, n));

		if (num > n) num = n;
		if (num <= 0)
		{
			DEBUG(5,("read_pipe: 0 or -ve data length\n"));
			return 0;
		}

		if (!IS_BITS_SET_ALL(p->hdr.flags, RPC_FLG_LAST))
		{
			/* intermediate fragment - possibility of another header */

			DEBUG(5,("read_pipe: frag_len: %d data_pos: %d data_hdr_pos: %d\n",
			          p->hdr.frag_len, data_pos, data_hdr_pos));

			if (data_hdr_pos == p->next_frag_start)
			{
				DEBUG(6,("read_pipe: next fragment header\n"));

				/* this is subtracted from the total data bytes, later */
				hdr_num = 0x18;

				/* create and copy in a new header. */
				create_rpc_reply(p, data_pos, p->rdata.offset);
				mem_buf_copy(data, p->rhdr.data, 0, 0x18);

				data += 0x18;
				p->frag_len_left = p->hdr.frag_len;
				p->next_frag_start += p->hdr.frag_len;
				p->hdr_offsets += 0x18;

				/*DEBUG(6,("read_pipe: hdr_offsets: %d\n", p->hdr_offsets));*/
			}
		}

		if (num < hdr_num)
		{
			DEBUG(5,("read_pipe: warning - data read only part of a header\n"));
		}

		DEBUG(6,("read_pipe: adjusted data_pos: %d num-hdr_num: %d\n",
				  data_pos, num - hdr_num));
		mem_buf_copy(data, p->rhdr.data, data_pos, num - hdr_num);

		data_pos += num;
		data_hdr_pos += num;

		if (hdr_num == 0x18 && num == 0x18)
		{
			DEBUG(6,("read_pipe: just header read\n"));

			/* advance to the next fragment */
			p->frag_len_left -= 0x18; 
		}
		else if (data_hdr_pos == p->next_frag_start)
		{
			DEBUG(6,("read_pipe: next fragment expected\n"));
		}

		p->file_offset  += num;

		return num;

	}
	else
	{
		DEBUG(6,("NOT\n"));
		return -1;
	}
}

/****************************************************************************
  gets the name of a pipe
****************************************************************************/
BOOL get_rpc_pipe(int pnum, pipes_struct **p)
{
	DEBUG(6,("get_rpc_pipe: "));

	/* mapping is PIPE_HANDLE_OFFSET up... */

	if (VALID_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		DEBUG(6,("name: %s open: %s ",
		          Pipes[pnum - PIPE_HANDLE_OFFSET].name,
		          BOOLSTR(Pipes[pnum - PIPE_HANDLE_OFFSET].open)));
	}
	if (OPEN_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		DEBUG(6,("OK\n"));
		(*p) = &(Pipes[pnum - PIPE_HANDLE_OFFSET]);
		return True;
	}
	else
	{
		DEBUG(6,("NOT\n"));
		return False;
	}
}

/****************************************************************************
  gets the name of a pipe
****************************************************************************/
char *get_rpc_pipe_hnd_name(int pnum)
{
	pipes_struct *p = NULL;
	get_rpc_pipe(pnum, &p);
	return p != NULL ? p->name : NULL;
}

/****************************************************************************
  set device state on a pipe.  exactly what this is for is unknown...
****************************************************************************/
BOOL set_rpc_pipe_hnd_state(pipes_struct *p, uint16 device_state)
{
	if (p == NULL) return False;

	if (P_OPEN(p))
	{
		DEBUG(3,("%s Setting pipe device state=%x on pipe (name=%s)\n",
		         timestring(), device_state, p->name));

		p->device_state = device_state;
   
		return True;
	}
	else
	{
		DEBUG(3,("%s Error setting pipe device state=%x (name=%s)\n",
		          timestring(), device_state, p->name));
		return False;
	}
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
BOOL close_rpc_pipe_hnd(int pnum, connection_struct *conn)
{
	pipes_struct *p = NULL;
	get_rpc_pipe(pnum, &p);
	/* mapping is PIPE_HANDLE_OFFSET up... */

	if (p != NULL && P_OK(p, conn)) {
		DEBUG(3,("%s Closed pipe name %s pnum=%x\n",
			 timestring(),Pipes[pnum-PIPE_HANDLE_OFFSET].name,
			 pnum));
  
		p->open = False;
		
		p->rdata.offset = 0;
		p->rhdr.offset = 0;
		mem_buf_free(&(p->rdata.data));
		mem_buf_free(&(p->rhdr .data));
		
		return True;
	} else {
		DEBUG(3,("%s Error closing pipe pnum=%x\n",
			 timestring(),pnum));
		return False;
	}
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
int get_rpc_pipe_num(char *buf, int where)
{
	return (chain_pnum != -1 ? chain_pnum : SVAL(buf,where));
}

