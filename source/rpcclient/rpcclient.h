/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client

   Copyright (C) Tim Potter 2000

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

#ifndef RPCCLIENT_H
#define RPCCLIENT_H

struct cmd_set {
	const char *name;
	NTSTATUS (*fn)(struct cli_state*, TALLOC_CTX *mem_ctx, int argc, 
                       char **argv);
        const char *pipe;
	const char *description;
	const char *usage;
};

#endif /* RPCCLIENT_H */
