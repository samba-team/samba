
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
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
	struct msrpc_state *m = NULL;
	user_struct *vuser = get_valid_user_struct(vuid);
	struct user_creds usr;

	ZERO_STRUCT(usr);

	DEBUG(4,("Open pipe requested %s by vuid %d (pipes_open=%d)\n",
		 pipe_name, vuid, pipes_open));
	
	if (vuser == NULL)
	{
		DEBUG(4,("invalid vuid %d\n", vuid));
		return NULL;
	}

	/* set up unix credentials from the smb side, to feed over the pipe */
	usr.ptr_uxc = 1;
	make_creds_unix(&usr.uxc, vuser->name, vuser->requested_name,
	                              vuser->real_name, vuser->guest);
	usr.ptr_uxs = 1;
	make_creds_unix_sec(&usr.uxs, vuser->uid, vuser->gid,
	                              vuser->n_groups, vuser->groups);
	usr.ptr_ssk = 1;
	memcpy(usr.usr_sess_key, vuser->user_sess_key, sizeof(usr.usr_sess_key));

	/* set up nt credentials from the smb side, to feed over the pipe */
	/* lkclXXXX todo!
	make_creds_nt(&usr.ntc);
	make_creds_nt_sec(&usr.nts);
	*/

	/* not repeating pipe numbers makes it easier to track things in 
	   log files and prevents client bugs where pipe numbers are reused
	   over connection restarts */
	if (next_pipe == 0)
	{
		next_pipe = (getpid() ^ time(NULL)) % MAX_OPEN_PIPES;
	}

	i = bitmap_find(bmap, next_pipe);

	if (i == -1)
	{
		DEBUG(0,("ERROR! Out of pipe structures\n"));
		return NULL;
	}

	next_pipe = (i+1) % MAX_OPEN_PIPES;

	for (p = Pipes; p; p = p->next)
	{
		DEBUG(5,("open pipes: name %s pnum=%x\n", p->name, p->pnum));  
	}

	become_root(False); /* to make pipe connection */
	m = msrpc_use_add(pipe_name, &usr, False);
	unbecome_root(False);

	if (m == NULL)
	{
		DEBUG(5,("open pipes: msrpc redirect failed\n"));
		return NULL;
	}

	p = (pipes_struct *)malloc(sizeof(*p));
	if (!p) return NULL;

	ZERO_STRUCTP(p);
	DLIST_ADD(Pipes, p);

	bitmap_set(bmap, i);
	i += pipe_handle_offset;

	pipes_open++;

	p->pnum = i;
	p->m = m;

	p->open = True;
	p->device_state = 0;
	p->priority = 0;
	p->conn = conn;
	p->vuid  = vuid;
	
	fstrcpy(p->name, pipe_name);

	DEBUG(4,("Opened pipe %s with handle %x (pipes_open=%d)\n",
		 pipe_name, i, pipes_open));
	
	chain_p = p;
	
	/* OVERWRITE p as a temp variable, to display all open pipes */ 
	for (p = Pipes; p; p = p->next)
	{
		DEBUG(5,("open pipes: name %s pnum=%x\n", p->name, p->pnum));  
	}

	return chain_p;
}



/****************************************************************************
  wait device state on a pipe.  exactly what this is for is unknown...
****************************************************************************/
BOOL wait_rpc_pipe_hnd_state(pipes_struct *p, uint16 priority)
{
	if (p == NULL) return False;

	if (p->open)
	{
		DEBUG(3,("%s Setting pipe wait state priority=%x on pipe (name=%s)\n",
		         timestring(), priority, p->name));

		p->priority = priority;
		
		return True;
	} 

	DEBUG(3,("%s Error setting pipe wait state priority=%x (name=%s)\n",
		 timestring(), priority, p->name));
	return False;
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

	bitmap_clear(bmap, p->pnum - pipe_handle_offset);

	pipes_open--;

	DEBUG(4,("closed pipe name %s pnum=%x (pipes_open=%d)\n", 
		 p->name, p->pnum, pipes_open));  

	DLIST_REMOVE(Pipes, p);

	if (p->m != NULL)
	{
		DEBUG(4,("closed msrpc redirect: "));
		if (msrpc_use_del(p->m->pipe_name, &p->m->usr, False, NULL))
		{
			DEBUG(4,("OK\n"));
		}
		else
		{
			DEBUG(4,("FAILED\n"));
		}
	}

	ZERO_STRUCTP(p);
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

	DEBUG(4,("search for pipe pnum=%x\n", pnum));

	for (p=Pipes;p;p=p->next)
	{
		DEBUG(5,("pipe name %s pnum=%x (pipes_open=%d) (open=%s)\n", 
		          p->name, p->pnum, pipes_open, BOOLSTR(p->open)));  
	}

	for (p=Pipes;p;p=p->next)
	{
		if (p->pnum == pnum)
		{
			chain_p = p;
			return p;
		}
	}

	return NULL;
}

