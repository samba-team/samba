/* 
   Unix SMB/CIFS implementation.
   DCERPC interface structures

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003
   
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

/*
  see http://www.opengroup.org/onlinepubs/9629399/chap12.htm for details
  of these structures

  note that the structure definitions here don't include some of the
  fields that are wire-artifacts. Those are put on the wire by the
  marshalling/unmarshalling routines in decrpc.c
*/

struct dcerpc_pipe {
	TALLOC_CTX *mem_ctx;
	uint16 fnum;
	int reference_count;
	uint32 call_id;
	uint32 srv_max_xmit_frag;
	uint32 srv_max_recv_frag;
	struct cli_tree *tree;
	unsigned flags;
};

/* dcerpc pipe flags */
#define DCERPC_DEBUG_PRINT_IN  1
#define DCERPC_DEBUG_PRINT_OUT 2
#define DCERPC_DEBUG_PRINT_BOTH (DCERPC_DEBUG_PRINT_IN | DCERPC_DEBUG_PRINT_OUT)

#define DCERPC_DEBUG_VALIDATE_IN  4
#define DCERPC_DEBUG_VALIDATE_OUT 8
#define DCERPC_DEBUG_VALIDATE_BOTH (DCERPC_DEBUG_VALIDATE_IN | DCERPC_DEBUG_VALIDATE_OUT)
