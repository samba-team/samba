
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Jeremy Allison				    1999.
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
static pipes_struct *chain_p;
static int pipes_open;

#ifndef MAX_OPEN_PIPES
#define MAX_OPEN_PIPES 64
#endif

static pipes_struct *Pipes;
static struct bitmap *bmap;

/* this must be larger than the sum of the open files and directories */
static int pipe_handle_offset;

/****************************************************************************
 Set the pipe_handle_offset. Called from smbd/files.c
****************************************************************************/

void set_pipe_handle_offset(int max_open_files)
{
  if(max_open_files < 0x7000)
    pipe_handle_offset = 0x7000;
  else
    pipe_handle_offset = max_open_files + 10; /* For safety. :-) */
}

/****************************************************************************
 Reset pipe chain handle number.
****************************************************************************/
void reset_chain_p(void)
{
	chain_p = NULL;
}

/****************************************************************************
 Initialise pipe handle states.
****************************************************************************/

void init_rpc_pipe_hnd(void)
{
	bmap = bitmap_allocate(MAX_OPEN_PIPES);
	if (!bmap)
		exit_server("out of memory in init_rpc_pipe_hnd\n");
}

/****************************************************************************
 Initialise an outgoing packet.
****************************************************************************/

BOOL pipe_init_outgoing_data( pipes_struct *p)
{

	memset(p->current_pdu, '\0', sizeof(p->current_pdu));

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&p->rdata);

	/*
	 * Initialize the outgoing RPC data buffer.
	 * we will use this as the raw data area for replying to rpc requests.
	 */	
	if(!prs_init(&p->rdata, 1024, 4, MARSHALL)) {
		DEBUG(0,("pipe_init_outgoing_data: malloc fail.\n"));
		return False;
	}

	/* Reset the offset counters. */
	p->data_sent_length = 0;
	p->current_pdu_len = 0;
	p->current_pdu_sent = 0;

	return True;
}

/****************************************************************************
 Find first available pipe slot.
****************************************************************************/

pipes_struct *open_rpc_pipe_p(char *pipe_name, 
			      connection_struct *conn, uint16 vuid)
{
	int i;
	pipes_struct *p;
	static int next_pipe;

	DEBUG(4,("Open pipe requested %s (pipes_open=%d)\n",
		 pipe_name, pipes_open));
	
	/* not repeating pipe numbers makes it easier to track things in 
	   log files and prevents client bugs where pipe numbers are reused
	   over connection restarts */
	if (next_pipe == 0)
		next_pipe = (getpid() ^ time(NULL)) % MAX_OPEN_PIPES;

	i = bitmap_find(bmap, next_pipe);

	if (i == -1) {
		DEBUG(0,("ERROR! Out of pipe structures\n"));
		return NULL;
	}

	next_pipe = (i+1) % MAX_OPEN_PIPES;

	for (p = Pipes; p; p = p->next)
		DEBUG(5,("open pipes: name %s pnum=%x\n", p->name, p->pnum));  

	p = (pipes_struct *)malloc(sizeof(*p));
	if (!p)
		return NULL;

	ZERO_STRUCTP(p);

	/*
	 * Initialize the RPC and PDU data buffers with no memory.
	 */	
	prs_init(&p->rdata, 0, 4, MARSHALL);
	
	DLIST_ADD(Pipes, p);

	bitmap_set(bmap, i);
	i += pipe_handle_offset;

	pipes_open++;

	p->pnum = i;

	p->open = True;
	p->device_state = 0;
	p->priority = 0;
	p->conn = conn;
	p->vuid  = vuid;

	p->max_trans_reply = 0;
	
	p->ntlmssp_chal_flags = 0;
	p->ntlmssp_auth_validated = False;
	p->ntlmssp_auth_requested = False;

	p->current_pdu_len = 0;
	p->current_pdu_sent = 0;
	p->data_sent_length = 0;

	p->uid = (uid_t)-1;
	p->gid = (gid_t)-1;
	
	fstrcpy(p->name, pipe_name);
	
	DEBUG(4,("Opened pipe %s with handle %x (pipes_open=%d)\n",
		 pipe_name, i, pipes_open));
	
	chain_p = p;
	
	/* OVERWRITE p as a temp variable, to display all open pipes */ 
	for (p = Pipes; p; p = p->next)
		DEBUG(5,("open pipes: name %s pnum=%x\n", p->name, p->pnum));  

	return chain_p;
}


/****************************************************************************
 Accepts incoming data on an rpc pipe.

 This code is probably incorrect at the moment. The problem is
 that the rpc request shouldn't really be executed until all the
 data needed for it is received. This currently assumes that each
 SMBwrite or SMBwriteX contains all the data needed for an rpc
 request. JRA.
 ****************************************************************************/

ssize_t write_to_pipe(pipes_struct *p, char *data, size_t n)
{
	DEBUG(6,("write_pipe: %x", p->pnum));

	DEBUG(6,("name: %s open: %s len: %d",
		 p->name, BOOLSTR(p->open), (int)n));

	dump_data(50, data, n);

	return rpc_command(p, data, (int)n) ? ((ssize_t)n) : -1;
}


/****************************************************************************
 Replyies to a request to read data from a pipe.

 Headers are interspersed with the data at PDU intervals. By the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 Calling create_rpc_reply() here is a hack. The data should already
 have been prepared into arrays of headers + data stream sections.

 ****************************************************************************/

int read_from_pipe(pipes_struct *p, char *data, int n)
{
	uint32 pdu_remaining = 0;
	int data_returned = 0;

	if (!p || !p->open) {
		DEBUG(0,("read_from_pipe: pipe not open\n"));
		return -1;		
	}

	DEBUG(6,("read_from_pipe: %x", p->pnum));

	DEBUG(6,("name: %s len: %d\n", p->name, n));

	/*
	 * We cannot return more than one PDU length per
	 * read request.
	 */

	if(n > MAX_PDU_FRAG_LEN) {
		DEBUG(0,("read_from_pipe: loo large read (%d) requested on pipe %s. We can \
only service %d sized reads.\n", n, p->name, MAX_PDU_FRAG_LEN ));
		return -1;
	}

	/*
 	 * Determine if there is still data to send in the
	 * pipe PDU buffer. Always send this first. Never
	 * send more than is left in the current PDU. The
	 * client should send a new read request for a new
	 * PDU.
	 */

	if((pdu_remaining = p->current_pdu_len - p->current_pdu_sent) > 0) {
		data_returned = MIN(n, pdu_remaining);

		DEBUG(10,("read_from_pipe: %s: current_pdu_len = %u, current_pdu_sent = %u \
returning %d bytes.\n", p->name, (unsigned int)p->current_pdu_len, 
			(unsigned int)p->current_pdu_sent, (int)data_returned));

		memcpy( data, &p->current_pdu[p->current_pdu_sent], (size_t)data_returned);
		p->current_pdu_sent += (uint32)data_returned;
		return data_returned;
	}

	/*
	 * At this point p->current_pdu_len == p->current_pdu_sent (which
	 * may of course be zero if this is the first return fragment.
	 */

	DEBUG(10,("read_from_pipe: %s: data_sent_length = %u, prs_offset(&p->rdata) = %u.\n",
		p->name, (unsigned int)p->data_sent_length, (unsigned int)prs_offset(&p->rdata) ));

	if(p->data_sent_length >= prs_offset(&p->rdata)) {
		/*
		 * We have sent all possible data. Return 0.
		 */
		return 0;
	}

	/*
	 * We need to create a new PDU from the data left in p->rdata.
	 * Create the header/data/footers. This also sets up the fields
	 * p->current_pdu_len, p->current_pdu_sent, p->data_sent_length
	 * and stores the outgoing PDU in p->current_pdu.
	 */

	if(!create_next_pdu(p)) {
		DEBUG(0,("read_from_pipe: %s: create_next_pdu failed.\n",
			 p->name));
		return -1;
	}

	data_returned = MIN(n, p->current_pdu_len);

	memcpy( data, p->current_pdu, (size_t)data_returned);
	p->current_pdu_sent += (uint32)data_returned;
	return data_returned;
}

/****************************************************************************
 Wait device state on a pipe. Exactly what this is for is unknown...
****************************************************************************/

BOOL wait_rpc_pipe_hnd_state(pipes_struct *p, uint16 priority)
{
	if (p == NULL)
		return False;

	if (p->open) {
		DEBUG(3,("wait_rpc_pipe_hnd_state: Setting pipe wait state priority=%x on pipe (name=%s)\n",
		         priority, p->name));

		p->priority = priority;
		
		return True;
	} 

	DEBUG(3,("wait_rpc_pipe_hnd_state: Error setting pipe wait state priority=%x (name=%s)\n",
		 priority, p->name));
	return False;
}


/****************************************************************************
 Set device state on a pipe. Exactly what this is for is unknown...
****************************************************************************/

BOOL set_rpc_pipe_hnd_state(pipes_struct *p, uint16 device_state)
{
	if (p == NULL)
		return False;

	if (p->open) {
		DEBUG(3,("set_rpc_pipe_hnd_state: Setting pipe device state=%x on pipe (name=%s)\n",
		         device_state, p->name));

		p->device_state = device_state;
		
		return True;
	} 

	DEBUG(3,("set_rpc_pipe_hnd_state: Error setting pipe device state=%x (name=%s)\n",
		 device_state, p->name));
	return False;
}


/****************************************************************************
 Close an rpc pipe.
****************************************************************************/

BOOL close_rpc_pipe_hnd(pipes_struct *p, connection_struct *conn)
{
	if (!p) {
		DEBUG(0,("Invalid pipe in close_rpc_pipe_hnd\n"));
		return False;
	}

	prs_mem_free(&p->rdata);

	bitmap_clear(bmap, p->pnum - pipe_handle_offset);

	pipes_open--;

	DEBUG(4,("closed pipe name %s pnum=%x (pipes_open=%d)\n", 
		 p->name, p->pnum, pipes_open));  

	DLIST_REMOVE(Pipes, p);

	ZERO_STRUCTP(p);

	free(p);
	
	return True;
}

/****************************************************************************
 Find an rpc pipe given a pipe handle in a buffer and an offset.
****************************************************************************/

pipes_struct *get_rpc_pipe_p(char *buf, int where)
{
	int pnum = SVAL(buf,where);

	if (chain_p)
		return chain_p;

	return get_rpc_pipe(pnum);
}

/****************************************************************************
 Find an rpc pipe given a pipe handle.
****************************************************************************/

pipes_struct *get_rpc_pipe(int pnum)
{
	pipes_struct *p;

	DEBUG(4,("search for pipe pnum=%x\n", pnum));

	for (p=Pipes;p;p=p->next)
		DEBUG(5,("pipe name %s pnum=%x (pipes_open=%d)\n", 
		          p->name, p->pnum, pipes_open));  

	for (p=Pipes;p;p=p->next) {
		if (p->pnum == pnum) {
			chain_p = p;
			return p;
		}
	}

	return NULL;
}
