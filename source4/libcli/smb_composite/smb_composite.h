/* 
   Unix SMB/CIFS implementation.

   SMB composite request interfaces

   Copyright (C) Andrew Tridgell 2005
   
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
  this defines the structures associated with "composite"
  requests. Composite requests are libcli requests that are internally
  implemented as multiple libcli/raw/ calls, but can be treated as a
  single call via these composite calls. The composite calls are
  particularly designed to be used in async applications
*/


/*
  a composite open/read(s)/close request that loads a whole file
  into memory. Used as a demo of the composite system.
*/
struct smb_composite_loadfile {
	struct {
		const char *fname;
	} in;
	struct {
		uint8_t *data;
		uint32_t size;
	} out;
};

struct smb_composite_fetchfile {
	struct {
		const char *dest_host;
		int port;
		const char *called_name;
		const char *service;
		const char *service_type;
		struct cli_credentials *credentials;
		const char *workgroup;
		const char *filename;
	} in;
	struct {
		uint8_t *data;
		uint32_t size;
	} out;
};

/*
  a composite open/write(s)/close request that saves a whole file from
  memory. Used as a demo of the composite system.
*/
struct smb_composite_savefile {
	struct {
		const char *fname;
		uint8_t *data;
		uint32_t size;
	} in;
};


/*
  a composite request for a full connection to a remote server. Includes

    - socket establishment
    - session request
    - negprot
    - session setup
    - tree connect
*/
struct smb_composite_connect {
	struct {
		const char *dest_host;
		int port;
		const char *called_name;
		const char *service;
		const char *service_type;
		struct cli_credentials *credentials;
		BOOL fallback_to_anonymous;
		const char *workgroup;
	} in;
	struct {
		struct smbcli_tree *tree;
		BOOL anonymous_fallback_done;
	} out;
};


/*
  generic session setup interface that takes care of which
  session setup varient to use
*/
struct smb_composite_sesssetup {
	struct {
		uint32_t sesskey;
		uint32_t capabilities;
		struct cli_credentials *credentials;
		const char *workgroup;
	} in;
	struct {
		uint16_t vuid;
	} out;		
};

/*
  query file system info
*/
struct smb_composite_fsinfo {
	struct {
		const char *dest_host;
		int port;
		const char *called_name;
		const char *service;
		const char *service_type;
		struct cli_credentials *credentials;
		const char *workgroup;
		enum smb_fsinfo_level level;
	} in;
	
	struct {
		union smb_fsinfo *fsinfo;
	} out;
};

/*
  composite call for appending new acl to the file's security descriptor and get 
  new full acl
*/

struct smb_composite_appendacl {
	struct {
		const char *fname;

		const struct security_descriptor *sd;
	} in;
	
	struct {
		struct security_descriptor *sd;
	} out;
};

/*
  a composite API to fire connect() calls to multiple targets, picking the
  first one.
*/

struct smb_composite_connectmulti {
	struct {
		int num_dests;
		const char **hostnames;
		const char **addresses;
		int *ports; 	/* Either NULL for lp_smb_ports() per
				 * destination or a list of explicit ports */
	} in;
	struct {
		struct smbcli_socket *socket;
	} out;
};

struct smbcli_session;

#include "libcli/smb_composite/proto.h"
