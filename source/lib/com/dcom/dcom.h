/* 
   Unix SMB/CIFS implementation.
   COM standard objects
   Copyright (C) Jelmer Vernooij					  2004-2005.
   
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

#ifndef _DCOM_H /* _DCOM_H */
#define _DCOM_H 

#include "lib/com/com.h"

struct dcom_client_context {
	struct cli_credentials *credentials;
	struct dcom_object_exporter {
		uint64_t oxid;	
		struct DUALSTRINGARRAY bindings;
		struct dcerpc_pipe *pipe;
		struct dcom_object_exporter *prev, *next;
	} *object_exporters;
};

#endif /* _DCOM_H */
