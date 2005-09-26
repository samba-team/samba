/* 
   Unix SMB/CIFS implementation.
   Main winbindd samba3 server routines

   Copyright (C) Stefan Metzmacher	2005
   Copyright (C) Volker Lendecke	2005

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

struct wbsrv_samba3_call {
	/* pointer back to the generic winbind call */
	struct wbsrv_call *call;

	/* here the backend can store stuff like composite_context's ... */
	void *private_data;

	/* the request structure of the samba3 protocol */
	struct winbindd_request request;
	
	/* the response structure of the samba3 protocol*/
	struct winbindd_response response;
};

#define WBSRV_SAMBA3_SET_STRING(dest, src) do { \
	strncpy(dest, src, sizeof(dest)-1);\
} while(0)
