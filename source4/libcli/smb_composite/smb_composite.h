/* 
   Unix SMB/CIFS implementation.

   SMB composite request interfaces

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  this defines the structures associated with "composite"
  requests. Composite requests are libcli requests that are internally
  implemented as multiple libcli/raw/ calls, but can be treated as a
  single call via these composite calls. The composite calls are
  particularly designed to be used in async applications
*/

#ifndef __SMB_COMPOSITE_H__
#define __SMB_COMPOSITE_H__

#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"

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

struct composite_context *smb_composite_loadfile_send(struct smbcli_tree *tree, 
						     struct smb_composite_loadfile *io);
NTSTATUS smb_composite_loadfile_recv(struct composite_context *c, TALLOC_CTX *mem_ctx);
NTSTATUS smb_composite_loadfile(struct smbcli_tree *tree, 
				TALLOC_CTX *mem_ctx,
				struct smb_composite_loadfile *io);

struct smb_composite_fetchfile {
	struct {
		const char *dest_host;
		const char **ports;
		const char *called_name;
		const char *service;
		const char *service_type;
		const char *socket_options;
		struct cli_credentials *credentials;
		const char *workgroup;
		const char *filename;
		struct smbcli_options options;
		struct smbcli_session_options session_options;
		struct resolve_context *resolve_ctx;
		struct gensec_settings *gensec_settings;
	} in;
	struct {
		uint8_t *data;
		uint32_t size;
	} out;
};

struct composite_context *smb_composite_fetchfile_send(struct smb_composite_fetchfile *io,
						       struct tevent_context *event_ctx);
NTSTATUS smb_composite_fetchfile_recv(struct composite_context *c,
				      TALLOC_CTX *mem_ctx);
NTSTATUS smb_composite_fetchfile(struct smb_composite_fetchfile *io,
				 TALLOC_CTX *mem_ctx);

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

struct composite_context *smb_composite_savefile_send(struct smbcli_tree *tree, 
						      struct smb_composite_savefile *io);
NTSTATUS smb_composite_savefile_recv(struct composite_context *c);
NTSTATUS smb_composite_savefile(struct smbcli_tree *tree, 
				struct smb_composite_savefile *io);

/*
  a composite request for a full connection to a remote server. Includes

    - socket establishment
    - session request
    - negprot
    - session setup (if credentials are not NULL)
    - tree connect (if service is not NULL)
*/
struct smb_composite_connect {
	struct {
		const char *dest_host;
		const char **dest_ports;
		const char *socket_options;
		const char *called_name;
		const char *service;
		const char *service_type;
		struct cli_credentials *credentials;
		bool fallback_to_anonymous;
		const char *workgroup;
		struct smbcli_options options;
		struct smbcli_session_options session_options;
		struct gensec_settings *gensec_settings;
	} in;
	struct {
		struct smbcli_tree *tree;
		bool anonymous_fallback_done;
	} out;
};

struct composite_context *smb_composite_connect_send(struct smb_composite_connect *io,
						     TALLOC_CTX *mem_ctx,
						     struct resolve_context *resolve_ctx,
						     struct tevent_context *event_ctx);
NTSTATUS smb_composite_connect_recv(struct composite_context *c, TALLOC_CTX *mem_ctx);
NTSTATUS smb_composite_connect(struct smb_composite_connect *io, TALLOC_CTX *mem_ctx,
			       struct resolve_context *resolve_ctx,
			       struct tevent_context *ev);


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
		struct gensec_settings *gensec_settings;
	} in;
	struct {
		uint16_t vuid;
	} out;		
};

struct composite_context *smb_composite_sesssetup_send(struct smbcli_session *session, 
						       struct smb_composite_sesssetup *io);
NTSTATUS smb_composite_sesssetup_recv(struct composite_context *c);
NTSTATUS smb_composite_sesssetup(struct smbcli_session *session, struct smb_composite_sesssetup *io);

/*
  query file system info
*/
struct smb_composite_fsinfo {
	struct {
		const char *dest_host;
		const char **dest_ports;
		const char *socket_options;
		const char *called_name;
		const char *service;
		const char *service_type;
		struct cli_credentials *credentials;
		const char *workgroup;
		enum smb_fsinfo_level level;
		struct gensec_settings *gensec_settings;
	} in;
	
	struct {
		union smb_fsinfo *fsinfo;
	} out;
};

struct composite_context *smb_composite_fsinfo_send(struct smbcli_tree *tree, 
						    struct smb_composite_fsinfo *io,
						    struct resolve_context *resolve_ctx,
						    struct tevent_context *event_ctx);
NTSTATUS smb_composite_fsinfo_recv(struct composite_context *c, TALLOC_CTX *mem_ctx);
NTSTATUS smb_composite_fsinfo(struct smbcli_tree *tree, 
			      TALLOC_CTX *mem_ctx,
			      struct smb_composite_fsinfo *io,
			      struct resolve_context *resolve_ctx,
			      struct tevent_context *ev);

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

struct composite_context *smb_composite_appendacl_send(struct smbcli_tree *tree, 
							struct smb_composite_appendacl *io);
NTSTATUS smb_composite_appendacl_recv(struct composite_context *c, TALLOC_CTX *mem_ctx);
NTSTATUS smb_composite_appendacl(struct smbcli_tree *tree, 
				TALLOC_CTX *mem_ctx,
				struct smb_composite_appendacl *io);

/*
  a composite API to fire connect() calls to multiple targets, picking the
  first one.
*/

struct smb_composite_connectmulti {
	struct {
		int num_dests;
		const char **hostnames;
		const char **addresses;
		int *ports; 	/* Either NULL for lpcfg_smb_ports() per
				 * destination or a list of explicit ports */
	} in;
	struct {
		struct smbcli_socket *socket;
	} out;
};

struct smbcli_session;
struct resolve_context;

struct composite_context *smb2_composite_unlink_send(struct smb2_tree *tree, 
						     union smb_unlink *io);
NTSTATUS smb2_composite_unlink(struct smb2_tree *tree, union smb_unlink *io);
struct composite_context *smb2_composite_mkdir_send(struct smb2_tree *tree, 
						     union smb_mkdir *io);
NTSTATUS smb2_composite_mkdir(struct smb2_tree *tree, union smb_mkdir *io);
struct composite_context *smb2_composite_rmdir_send(struct smb2_tree *tree, 
						    struct smb_rmdir *io);
NTSTATUS smb2_composite_rmdir(struct smb2_tree *tree, struct smb_rmdir *io);
struct tevent_req *smb2_composite_setpathinfo_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct smb2_tree *tree,
						   const union smb_setfileinfo *io);
NTSTATUS smb2_composite_setpathinfo_recv(struct tevent_req *req);
NTSTATUS smb2_composite_setpathinfo(struct smb2_tree *tree, union smb_setfileinfo *io);

#endif /* __SMB_COMPOSITE_H__ */
