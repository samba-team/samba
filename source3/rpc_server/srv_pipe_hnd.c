
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

/* this must be larger than the sum of the open files and directories */
#define PIPE_HANDLE_OFFSET 0x7000

extern int DEBUGLEVEL;
static pipes_struct *chain_p;
static int pipes_open;

#ifndef MAX_OPEN_PIPES
#define MAX_OPEN_PIPES 64
#endif

static pipes_struct *Pipes;
static struct bitmap *bmap;

/****************************************************************************
  reset pipe chain handle number
****************************************************************************/
void reset_chain_p(void)
{
	chain_p = NULL;
}

/****************************************************************************
  initialise pipe handle states...
****************************************************************************/
void init_rpc_pipe_hnd(void)
{
	bmap = bitmap_allocate(MAX_OPEN_PIPES);
	if (!bmap) {
		exit_server("out of memory in init_rpc_pipe_hnd\n");
	}
}


/****************************************************************************
  find first available file slot
****************************************************************************/
pipes_struct *open_rpc_pipe_p(char *pipe_name, 
			      connection_struct *conn, uint16 vuid)
{
	int i;
	pipes_struct *p;
	static int next_pipe;

	/* not repeating pipe numbers makes it easier to track things in 
	   log files and prevents client bugs where pipe numbers are reused
	   over connection restarts */
	if (next_pipe == 0) {
		next_pipe = (getpid() ^ time(NULL)) % MAX_OPEN_PIPES;
	}

	i = bitmap_find(bmap, next_pipe);

	if (i == -1) {
		DEBUG(0,("ERROR! Out of pipe structures\n"));
		return NULL;
	}

	next_pipe = (i+1) % MAX_OPEN_PIPES;

	p = (pipes_struct *)malloc(sizeof(*p));
	if (!p) return NULL;

	DLIST_ADD(Pipes, p);

	bitmap_set(bmap, i);
	i += PIPE_HANDLE_OFFSET;

	pipes_open++;

	memset(p, 0, sizeof(*p));
	p->pnum = i;

	p->open = True;
	p->device_state = 0;
	p->conn = conn;
	p->uid  = vuid;
	
	p->rhdr.data  = NULL;
	p->rdata.data = NULL;
	p->rhdr.offset  = 0;
	p->rdata.offset = 0;
	
	p->file_offset     = 0;
	p->hdr_offsets     = 0;
	p->frag_len_left   = 0;
	p->next_frag_start = 0;
	
	fstrcpy(p->name, pipe_name);
	
	DEBUG(4,("Opened pipe %s with handle %x (pipes_open=%d)\n",
		 pipe_name, i, pipes_open));
	
	chain_p = p;
	
	return p;
}


/****************************************************************************
 reads data from a pipe.

 headers are interspersed with the data at regular intervals.  by the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 calling create_rpc_request() here is a fudge.  the data should already
 have been prepared into arrays of headers + data stream sections.

 ****************************************************************************/
int read_pipe(pipes_struct *p, char *data, uint32 pos, int n)
{
	int num = 0;
	int len = 0;
	uint32 hdr_num = 0;
	int data_hdr_pos;
	int data_pos;

	DEBUG(6,("read_pipe: %x", p->pnum));

	DEBUG(6,("name: %s open: %s pos: %d len: %d",
		 p->name,
		 BOOLSTR(p->open),
		 pos, n));

	if (!p || !p->open) {
		DEBUG(6,("pipe not open\n"));
		return -1;		
	}


	if (p->rhdr.data == NULL || p->rhdr.data->data == NULL ||
	    p->rhdr.data->data_used == 0) {
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
	if (num <= 0) {
		DEBUG(5,("read_pipe: 0 or -ve data length\n"));
		return 0;
	}

	if (!IS_BITS_SET_ALL(p->hdr.flags, RPC_FLG_LAST)) {
		/* intermediate fragment - possibility of another header */
		
		DEBUG(5,("read_pipe: frag_len: %d data_pos: %d data_hdr_pos: %d\n",
			 p->hdr.frag_len, data_pos, data_hdr_pos));
		
		if (data_hdr_pos == p->next_frag_start)	{
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
		}			
		
	}
	
	if (num < hdr_num) {
		DEBUG(5,("read_pipe: warning - data read only part of a header\n"));
	}

	DEBUG(6,("read_pipe: adjusted data_pos: %d num-hdr_num: %d\n",
		 data_pos, num - hdr_num));
	mem_buf_copy(data, p->rhdr.data, data_pos, num - hdr_num);
	
	data_pos += num;
	data_hdr_pos += num;
	
	if (hdr_num == 0x18 && num == 0x18) {
		DEBUG(6,("read_pipe: just header read\n"));

		/* advance to the next fragment */
		p->frag_len_left -= 0x18; 
	} else if (data_hdr_pos == p->next_frag_start) {
		DEBUG(6,("read_pipe: next fragment expected\n"));
	}

	p->file_offset  += num;
	
	return num;
}


/****************************************************************************
  set device state on a pipe.  exactly what this is for is unknown...
****************************************************************************/
BOOL set_rpc_pipe_hnd_state(pipes_struct *p, uint16 device_state)
{
	if (p == NULL) return False;

	if (p->open) {
		DEBUG(3,("%s Setting pipe device state=%x on pipe (name=%s)\n",
		         timestring(), device_state, p->name));

		p->device_state = device_state;
		
		return True;
	} 

	DEBUG(3,("%s Error setting pipe device state=%x (name=%s)\n",
		 timestring(), device_state, p->name));
	return False;
}


/****************************************************************************
  close an rpc pipe
****************************************************************************/
BOOL close_rpc_pipe_hnd(pipes_struct *p, connection_struct *conn)
{
	if (!p) {
		DEBUG(0,("Invalid pipe in close_rpc_pipe_hnd\n"));
		return False;
	}

	mem_buf_free(&(p->rdata.data));
	mem_buf_free(&(p->rhdr .data));

	bitmap_clear(bmap, p->pnum - PIPE_HANDLE_OFFSET);

	pipes_open--;

	DEBUG(4,("closed pipe name %s pnum=%x (pipes_open=%d)\n", 
		 p->name, p->pnum, pipes_open));  

	DLIST_REMOVE(Pipes, p);

	memset(p, 0, sizeof(*p));

	free(p);
	
	return True;
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
pipes_struct *get_rpc_pipe_p(char *buf, int where)
{
	int pnum = SVAL(buf,where);

	if (chain_p) return chain_p;

	return get_rpc_pipe(pnum);
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
pipes_struct *get_rpc_pipe(int pnum)
{
	pipes_struct *p;

	for (p=Pipes;p;p=p->next) {
		if (p->pnum == pnum) {
			chain_p = p;
			return p;
		}
	}

	return NULL;
}

