/* 
   Unix SMB/CIFS implementation.

   definitions for marshalling/unmarshalling the rpcecho pipe

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
  see http://samba.org/ftp/unpacked/junkcode/rpcecho-win32/ for the
  definition of this pipe
*/

/* AddOne interface */
struct rpcecho_addone {
	struct {
		int data;
	} in;
	struct {
		int data;
	} out;
};

/* EchoData interface */
struct rpcecho_echodata {
	struct {
		int len;
		const char *data;
	} in;
	struct {
		int len;
		char *data;
	} out;
};

/* SinkData interface */
struct rpcecho_sinkdata {
	struct {
		int len;
		char *data;
	} in;
};

/* SourceData interface */
struct rpcecho_sourcedata {
	struct {
		int len;
	} in;
	struct {
		int len;
		char *data;
	} out;
};

/* define the command codes */
enum {
	RPCECHO_CALL_ADDONE=0,
	RPCECHO_CALL_ECHODATA,
	RPCECHO_CALL_SINKDATA,
	RPCECHO_CALL_SOURCEDATA
};
	
