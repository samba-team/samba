/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "../utils/net.h"

int net_rpc_usage(int argc, const char **argv) 
{
	d_printf("  net rpc join \tto join a domin \n");
	return -1;
}

int net_rpc(int argc, const char **argv)
{
	struct functable func[] = {
		{"join", net_rpc_join},
		{NULL, NULL}
	};
	return net_run_function(argc, argv, func, net_rpc_usage);
}
