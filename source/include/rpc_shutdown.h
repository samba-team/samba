/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)      2003.
   
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

#ifndef _RPC_SHUTDOWN_H /* _RPC_SHUTDOWN_H */
#define _RPC_SHUTDOWN_H 


/* Implemented */
#define SHUTDOWN_INIT		0x00
#define SHUTDOWN_ABORT		0x01
/* NOT IMPLEMENTED
#define SHUTDOWN_INIT_EX	0x02
*/

/* SHUTDOWN_Q_INIT */
typedef struct q_shutodwn_init_info
{
	uint32 ptr_server;
	uint16 server;
	uint32 ptr_msg;
	UNIHDR hdr_msg;		/* shutdown message */
	UNISTR2 uni_msg;	/* seconds */
	uint32 timeout;		/* seconds */
	uint8 force;		/* boolean: force shutdown */
	uint8 reboot;		/* boolean: reboot on shutdown */
		
} SHUTDOWN_Q_INIT;

/* SHUTDOWN_R_INIT */
typedef struct r_shutdown_init_info
{
	NTSTATUS status;		/* return status */

} SHUTDOWN_R_INIT;

/* SHUTDOWN_Q_ABORT */
typedef struct q_shutdown_abort_info
{
	uint32 ptr_server;
	uint16 server;

} SHUTDOWN_Q_ABORT;

/* SHUTDOWN_R_ABORT */
typedef struct r_shutdown_abort_info
{ 
	NTSTATUS status; /* return status */

} SHUTDOWN_R_ABORT;


#endif /* _RPC_SHUTDOWN_H */

