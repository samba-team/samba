/*
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2007

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
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/

#include "includes.h"

/* look in server.c for some explanation of these variables */
extern enum protocol_types Protocol;
extern int max_recv;
extern uint32 global_client_caps;

extern bool global_encrypted_passwords_negotiated;

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for a findfirst/findnext
 path or anything including wildcards.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption). '\\' *may* be the second byte in a multibyte char
 set.
****************************************************************************/

/* Custom version for processing POSIX paths. */
#define IS_PATH_SEP(c,posix_only) ((c) == '/' || (!(posix_only) && (c) == '\\'))

static NTSTATUS check_path_syntax_internal(char *path,
					   bool posix_path,
					   bool *p_last_component_contains_wcard)
{
	char *d = path;
	const char *s = path;
	NTSTATUS ret = NT_STATUS_OK;
	bool start_of_name_component = True;
	bool stream_started = false;

	*p_last_component_contains_wcard = False;

	while (*s) {
		if (stream_started) {
			switch (*s) {
			case '/':
			case '\\':
				return NT_STATUS_OBJECT_NAME_INVALID;
			case ':':
				if (s[1] == '\0') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				if (strchr_m(&s[1], ':')) {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				if (StrCaseCmp(s, ":$DATA") != 0) {
					return NT_STATUS_INVALID_PARAMETER;
				}
				break;
			}
		}

		if (!posix_path && !stream_started && *s == ':') {
			if (*p_last_component_contains_wcard) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			/* Stream names allow more characters than file names.
			   We're overloading posix_path here to allow a wider
			   range of characters. If stream_started is true this
			   is still a Windows path even if posix_path is true.
			   JRA.
			*/
			stream_started = true;
			start_of_name_component = false;
			posix_path = true;

			if (s[1] == '\0') {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		}

		if (!stream_started && IS_PATH_SEP(*s,posix_path)) {
			/*
			 * Safe to assume is not the second part of a mb char
			 * as this is handled below.
			 */
			/* Eat multiple '/' or '\\' */
			while (IS_PATH_SEP(*s,posix_path)) {
				s++;
			}
			if ((d != path) && (*s != '\0')) {
				/* We only care about non-leading or trailing '/' or '\\' */
				*d++ = '/';
			}

			start_of_name_component = True;
			/* New component. */
			*p_last_component_contains_wcard = False;
			continue;
		}

		if (start_of_name_component) {
			if ((s[0] == '.') && (s[1] == '.') && (IS_PATH_SEP(s[2],posix_path) || s[2] == '\0')) {
				/* Uh oh - "/../" or "\\..\\"  or "/..\0" or "\\..\0" ! */

				/*
				 * No mb char starts with '.' so we're safe checking the directory separator here.
				 */

				/* If  we just added a '/' - delete it */
				if ((d > path) && (*(d-1) == '/')) {
					*(d-1) = '\0';
					d--;
				}

				/* Are we at the start ? Can't go back further if so. */
				if (d <= path) {
					ret = NT_STATUS_OBJECT_PATH_SYNTAX_BAD;
					break;
				}
				/* Go back one level... */
				/* We know this is safe as '/' cannot be part of a mb sequence. */
				/* NOTE - if this assumption is invalid we are not in good shape... */
				/* Decrement d first as d points to the *next* char to write into. */
				for (d--; d > path; d--) {
					if (*d == '/')
						break;
				}
				s += 2; /* Else go past the .. */
				/* We're still at the start of a name component, just the previous one. */
				continue;

			} else if ((s[0] == '.') && ((s[1] == '\0') || IS_PATH_SEP(s[1],posix_path))) {
				if (posix_path) {
					/* Eat the '.' */
					s++;
					continue;
				}
			}

		}

		if (!(*s & 0x80)) {
			if (!posix_path) {
				if (*s <= 0x1f || *s == '|') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				switch (*s) {
					case '*':
					case '?':
					case '<':
					case '>':
					case '"':
						*p_last_component_contains_wcard = True;
						break;
					default:
						break;
				}
			}
			*d++ = *s++;
		} else {
			size_t siz;
			/* Get the size of the next MB character. */
			next_codepoint(s,&siz);
			switch(siz) {
				case 5:
					*d++ = *s++;
					/*fall through*/
				case 4:
					*d++ = *s++;
					/*fall through*/
				case 3:
					*d++ = *s++;
					/*fall through*/
				case 2:
					*d++ = *s++;
					/*fall through*/
				case 1:
					*d++ = *s++;
					break;
				default:
					DEBUG(0,("check_path_syntax_internal: character length assumptions invalid !\n"));
					*d = '\0';
					return NT_STATUS_INVALID_PARAMETER;
			}
		}
		start_of_name_component = False;
	}

	*d = '\0';

	return ret;
}

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for regular pathnames.
 No wildcards allowed.
****************************************************************************/

NTSTATUS check_path_syntax(char *path)
{
	bool ignore;
	return check_path_syntax_internal(path, False, &ignore);
}

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for regular pathnames.
 Wildcards allowed - p_contains_wcard returns true if the last component contained
 a wildcard.
****************************************************************************/

NTSTATUS check_path_syntax_wcard(char *path, bool *p_contains_wcard)
{
	return check_path_syntax_internal(path, False, p_contains_wcard);
}

/****************************************************************************
 Check the path for a POSIX client.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption).
****************************************************************************/

NTSTATUS check_path_syntax_posix(char *path)
{
	bool ignore;
	return check_path_syntax_internal(path, True, &ignore);
}

/****************************************************************************
 Pull a string and check the path allowing a wilcard - provide for error return.
****************************************************************************/

size_t srvstr_get_path_wcard(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16 smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard)
{
	size_t ret;

	*pp_dest = NULL;

	if (src_len == 0) {
		ret = srvstr_pull_buf_talloc(ctx,
				inbuf,
				smb_flags2,
				pp_dest,
				src,
				flags);
	} else {
		ret = srvstr_pull_talloc(ctx,
				inbuf,
				smb_flags2,
				pp_dest,
				src,
				src_len,
				flags);
	}

	if (!*pp_dest) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return ret;
	}

	*contains_wcard = False;

	if (smb_flags2 & FLAGS2_DFS_PATHNAMES) {
		/*
		 * For a DFS path the function parse_dfs_path()
		 * will do the path processing, just make a copy.
		 */
		*err = NT_STATUS_OK;
		return ret;
	}

	if (lp_posix_pathnames()) {
		*err = check_path_syntax_posix(*pp_dest);
	} else {
		*err = check_path_syntax_wcard(*pp_dest, contains_wcard);
	}

	return ret;
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
****************************************************************************/

size_t srvstr_get_path(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16 smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err)
{
	size_t ret;

	*pp_dest = NULL;

	if (src_len == 0) {
		ret = srvstr_pull_buf_talloc(ctx,
					inbuf,
					smb_flags2,
					pp_dest,
					src,
					flags);
	} else {
		ret = srvstr_pull_talloc(ctx,
				inbuf,
				smb_flags2,
				pp_dest,
				src,
				src_len,
				flags);
	}

	if (!*pp_dest) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return ret;
	}

	if (smb_flags2 & FLAGS2_DFS_PATHNAMES) {
		/*
		 * For a DFS path the function parse_dfs_path()
		 * will do the path processing, just make a copy.
		 */
		*err = NT_STATUS_OK;
		return ret;
	}

	if (lp_posix_pathnames()) {
		*err = check_path_syntax_posix(*pp_dest);
	} else {
		*err = check_path_syntax(*pp_dest);
	}

	return ret;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a file. Basic check for open fsp.
****************************************************************************/

bool check_fsp_open(connection_struct *conn, struct smb_request *req,
		    files_struct *fsp)
{
	if (!(fsp) || !(conn)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return False;
	}
	if (((conn) != (fsp)->conn) || req->vuid != (fsp)->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return False;
	}
	return True;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a file.
****************************************************************************/

bool check_fsp(connection_struct *conn, struct smb_request *req,
	       files_struct *fsp)
{
	if (!check_fsp_open(conn, req, fsp)) {
		return False;
	}
	if ((fsp)->is_directory) {
		reply_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return False;
	}
	if ((fsp)->fh->fd == -1) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return False;
	}
	(fsp)->num_smb_operations++;
	return True;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a quota fake file. Replacement for
 the CHECK_NTQUOTA_HANDLE_OK macro.
****************************************************************************/

bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp)
{
	if (!check_fsp_open(conn, req, fsp)) {
		return false;
	}

	if (fsp->is_directory) {
		return false;
	}

	if (fsp->fake_file_handle == NULL) {
		return false;
	}

	if (fsp->fake_file_handle->type != FAKE_FILE_TYPE_QUOTA) {
		return false;
	}

	if (fsp->fake_file_handle->private_data == NULL) {
		return false;
	}

	return true;
}

/****************************************************************************
 Check if we have a correct fsp. Replacement for the FSP_BELONGS_CONN macro
****************************************************************************/

bool fsp_belongs_conn(connection_struct *conn, struct smb_request *req,
		      files_struct *fsp)
{
	if ((fsp) && (conn) && ((conn)==(fsp)->conn)
	    && (req->vuid == (fsp)->vuid)) {
		return True;
	}

	reply_nterror(req, NT_STATUS_INVALID_HANDLE);
	return False;
}

/****************************************************************************
 Reply to a (netbios-level) special message.
****************************************************************************/

void reply_special(char *inbuf)
{
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	fstring name1,name2;
	char name_type = 0;

	/*
	 * We only really use 4 bytes of the outbuf, but for the smb_setlen
	 * calculation & friends (srv_send_smb uses that) we need the full smb
	 * header.
	 */
	char outbuf[smb_size];
	
	static bool already_got_session = False;

	*name1 = *name2 = 0;
	
	memset(outbuf, '\0', sizeof(outbuf));

	smb_setlen(outbuf,0);
	
	switch (msg_type) {
	case 0x81: /* session request */
		
		if (already_got_session) {
			exit_server_cleanly("multiple session request not permitted");
		}
		
		SCVAL(outbuf,0,0x82);
		SCVAL(outbuf,3,0);
		if (name_len(inbuf+4) > 50 || 
		    name_len(inbuf+4 + name_len(inbuf + 4)) > 50) {
			DEBUG(0,("Invalid name length in session request\n"));
			return;
		}
		name_extract(inbuf,4,name1);
		name_type = name_extract(inbuf,4 + name_len(inbuf + 4),name2);
		DEBUG(2,("netbios connect: name1=%s name2=%s\n",
			 name1,name2));      

		set_local_machine_name(name1, True);
		set_remote_machine_name(name2, True);

		DEBUG(2,("netbios connect: local=%s remote=%s, name type = %x\n",
			 get_local_machine_name(), get_remote_machine_name(),
			 name_type));

		if (name_type == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			SCVAL(outbuf, 0,0x83);
			break;
		}

		/* only add the client's machine name to the list
		   of possibly valid usernames if we are operating
		   in share mode security */
		if (lp_security() == SEC_SHARE) {
			add_session_user(get_remote_machine_name());
		}

		reload_services(True);
		reopen_logs();

		already_got_session = True;
		break;
		
	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		SCVAL(outbuf,0,SMBkeepalive);
		SCVAL(outbuf,3,0);
		break;
		
	case 0x82: /* positive session response */
	case 0x83: /* negative session response */
	case 0x84: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;
		
	case SMBkeepalive: /* session keepalive */
	default:
		return;
	}
	
	DEBUG(5,("init msg_type=0x%x msg_flags=0x%x\n",
		    msg_type, msg_flags));

	srv_send_smb(smbd_server_fd(), outbuf, false);
	return;
}

/****************************************************************************
 Reply to a tcon.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	const char *service;
	char *service_buf = NULL;
	char *password = NULL;
	char *dev = NULL;
	int pwlen=0;
	NTSTATUS nt_status;
	char *p;
	DATA_BLOB password_blob;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBtcon);

	if (smb_buflen(req->inbuf) < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}

	p = smb_buf(req->inbuf)+1;
	p += srvstr_pull_buf_talloc(ctx, req->inbuf, req->flags2,
				    &service_buf, p, STR_TERMINATE) + 1;
	pwlen = srvstr_pull_buf_talloc(ctx, req->inbuf, req->flags2,
				       &password, p, STR_TERMINATE) + 1;
	p += pwlen;
	p += srvstr_pull_buf_talloc(ctx, req->inbuf, req->flags2,
				    &dev, p, STR_TERMINATE) + 1;

	if (service_buf == NULL || password == NULL || dev == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}
	p = strrchr_m(service_buf,'\\');
	if (p) {
		service = p+1;
	} else {
		service = service_buf;
	}

	password_blob = data_blob(password, pwlen+1);

	conn = make_connection(service,password_blob,dev,req->vuid,&nt_status);
	req->conn = conn;

	data_blob_clear_free(&password_blob);

	if (!conn) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtcon);
		return;
	}

	reply_outbuf(req, 2, 0);
	SSVAL(req->outbuf,smb_vwv0,max_recv);
	SSVAL(req->outbuf,smb_vwv1,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	DEBUG(3,("tcon service=%s cnum=%d\n",
		 service, conn->cnum));

	END_PROFILE(SMBtcon);
	return;
}

/****************************************************************************
 Reply to a tcon and X.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *service = NULL;
	DATA_BLOB password;
	TALLOC_CTX *ctx = talloc_tos();
	/* what the cleint thinks the device is */
	char *client_devicetype = NULL;
	/* what the server tells the client the share represents */
	const char *server_devicetype;
	NTSTATUS nt_status;
	int passlen;
	char *path = NULL;
	char *p, *q;
	uint16 tcon_flags;

	START_PROFILE(SMBtconX);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	passlen = SVAL(req->inbuf,smb_vwv3);
	tcon_flags = SVAL(req->inbuf,smb_vwv2);

	/* we might have to close an old one */
	if ((tcon_flags & 0x1) && conn) {
		close_cnum(conn,req->vuid);
		req->conn = NULL;
		conn = NULL;
	}

	if ((passlen > MAX_PASS_LEN) || (passlen >= smb_buflen(req->inbuf))) {
		reply_doserror(req, ERRDOS, ERRbuftoosmall);
		END_PROFILE(SMBtconX);
		return;
	}

	if (global_encrypted_passwords_negotiated) {
		password = data_blob_talloc(talloc_tos(), smb_buf(req->inbuf),
					    passlen);
		if (lp_security() == SEC_SHARE) {
			/*
			 * Security = share always has a pad byte
			 * after the password.
			 */
			p = smb_buf(req->inbuf) + passlen + 1;
		} else {
			p = smb_buf(req->inbuf) + passlen;
		}
	} else {
		password = data_blob_talloc(talloc_tos(), smb_buf(req->inbuf),
					    passlen+1);
		/* Ensure correct termination */
		password.data[passlen]=0;
		p = smb_buf(req->inbuf) + passlen + 1;
	}

	p += srvstr_pull_buf_talloc(ctx, req->inbuf, req->flags2, &path, p,
			     STR_TERMINATE);

	if (path == NULL) {
		data_blob_clear_free(&password);
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	/*
	 * the service name can be either: \\server\share
	 * or share directly like on the DELL PowerVault 705
	 */
	if (*path=='\\') {
		q = strchr_m(path+2,'\\');
		if (!q) {
			data_blob_clear_free(&password);
			reply_doserror(req, ERRDOS, ERRnosuchshare);
			END_PROFILE(SMBtconX);
			return;
		}
		service = q+1;
	} else {
		service = path;
	}

	p += srvstr_pull_talloc(ctx, req->inbuf, req->flags2,
				&client_devicetype, p,
				MIN(6,smb_bufrem(req->inbuf, p)), STR_ASCII);

	if (client_devicetype == NULL) {
		data_blob_clear_free(&password);
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	DEBUG(4,("Client requested device type [%s] for share [%s]\n", client_devicetype, service));

	conn = make_connection(service, password, client_devicetype,
			       req->vuid, &nt_status);
	req->conn =conn;

	data_blob_clear_free(&password);

	if (!conn) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtconX);
		return;
	}

	if ( IS_IPC(conn) )
		server_devicetype = "IPC";
	else if ( IS_PRINT(conn) )
		server_devicetype = "LPT1:";
	else
		server_devicetype = "A:";

	if (Protocol < PROTOCOL_NT1) {
		reply_outbuf(req, 2, 0);
		if (message_push_string(&req->outbuf, server_devicetype,
					STR_TERMINATE|STR_ASCII) == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
	} else {
		/* NT sets the fstype of IPC$ to the null string */
		const char *fstype = IS_IPC(conn) ? "" : lp_fstype(SNUM(conn));

		if (tcon_flags & TCONX_FLAG_EXTENDED_RESPONSE) {
			/* Return permissions. */
			uint32 perm1 = 0;
			uint32 perm2 = 0;

			reply_outbuf(req, 7, 0);

			if (IS_IPC(conn)) {
				perm1 = FILE_ALL_ACCESS;
				perm2 = FILE_ALL_ACCESS;
			} else {
				perm1 = CAN_WRITE(conn) ?
						SHARE_ALL_ACCESS :
						SHARE_READ_ONLY;
			}

			SIVAL(req->outbuf, smb_vwv3, perm1);
			SIVAL(req->outbuf, smb_vwv5, perm2);
		} else {
			reply_outbuf(req, 3, 0);
		}

		if ((message_push_string(&req->outbuf, server_devicetype,
					 STR_TERMINATE|STR_ASCII) == -1)
		    || (message_push_string(&req->outbuf, fstype,
					    STR_TERMINATE) == -1)) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}

		/* what does setting this bit do? It is set by NT4 and
		   may affect the ability to autorun mounted cdroms */
		SSVAL(req->outbuf, smb_vwv2, SMB_SUPPORT_SEARCH_BITS|
		      (lp_csc_policy(SNUM(conn)) << 2));

		init_dfsroot(conn, req->inbuf, req->outbuf);
	}


	DEBUG(3,("tconX service=%s \n",
		 service));

	/* set the incoming and outgoing tid to the just created one */
	SSVAL(req->inbuf,smb_tid,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	END_PROFILE(SMBtconX);

	chain_reply(req);
	return;
}

/****************************************************************************
 Reply to an unknown type.
****************************************************************************/

void reply_unknown_new(struct smb_request *req, uint8 type)
{
	DEBUG(0, ("unknown command type (%s): type=%d (0x%X)\n",
		  smb_fn_name(type), type, type));
	reply_doserror(req, ERRSRV, ERRunknownsmb);
	return;
}

/****************************************************************************
 Reply to an ioctl.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_ioctl(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint16 device;
	uint16 function;
	uint32 ioctl_code;
	int replysize;
	char *p;

	START_PROFILE(SMBioctl);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBioctl);
		return;
	}

	device     = SVAL(req->inbuf,smb_vwv1);
	function   = SVAL(req->inbuf,smb_vwv2);
	ioctl_code = (device << 16) + function;

	DEBUG(4, ("Received IOCTL (code 0x%x)\n", ioctl_code));

	switch (ioctl_code) {
	    case IOCTL_QUERY_JOB_INFO:
		    replysize = 32;
		    break;
	    default:
		    reply_doserror(req, ERRSRV, ERRnosupport);
		    END_PROFILE(SMBioctl);
		    return;
	}

	reply_outbuf(req, 8, replysize+1);
	SSVAL(req->outbuf,smb_vwv1,replysize); /* Total data bytes returned */
	SSVAL(req->outbuf,smb_vwv5,replysize); /* Data bytes this buffer */
	SSVAL(req->outbuf,smb_vwv6,52);        /* Offset to data */
	p = smb_buf(req->outbuf);
	memset(p, '\0', replysize+1); /* valgrind-safe. */
	p += 1;          /* Allow for alignment */

	switch (ioctl_code) {
		case IOCTL_QUERY_JOB_INFO:		    
		{
			files_struct *fsp = file_fsp(SVAL(req->inbuf,
							  smb_vwv0));
			if (!fsp) {
				reply_doserror(req, ERRDOS, ERRbadfid);
				END_PROFILE(SMBioctl);
				return;
			}
			SSVAL(p,0,fsp->rap_print_jobid);             /* Job number */
			srvstr_push((char *)req->outbuf, req->flags2, p+2,
				    global_myname(), 15,
				    STR_TERMINATE|STR_ASCII);
			if (conn) {
				srvstr_push((char *)req->outbuf, req->flags2,
					    p+18, lp_servicename(SNUM(conn)),
					    13, STR_TERMINATE|STR_ASCII);
			} else {
				memset(p+18, 0, 13);
			}
			break;
		}
	}

	END_PROFILE(SMBioctl);
	return;
}

/****************************************************************************
 Strange checkpath NTSTATUS mapping.
****************************************************************************/

static NTSTATUS map_checkpath_error(const char *inbuf, NTSTATUS status)
{
	/* Strange DOS error code semantics only for checkpath... */
	if (!(SVAL(inbuf,smb_flg2) & FLAGS2_32_BIT_ERROR_CODES)) {
		if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_INVALID,status)) {
			/* We need to map to ERRbadpath */
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
	}
	return status;
}

/****************************************************************************
 Reply to a checkpath.
****************************************************************************/

void reply_checkpath(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcheckpath);

	srvstr_get_path(ctx,(char *)req->inbuf, req->flags2, &name,
			smb_buf(req->inbuf) + 1, 0,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		status = map_checkpath_error((char *)req->inbuf, status);
		reply_nterror(req, status);
		END_PROFILE(SMBcheckpath);
		return;
	}

	status = resolve_dfspath(ctx, conn,
			req->flags2 & FLAGS2_DFS_PATHNAMES,
			name,
			&name);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBcheckpath);
			return;
		}
		goto path_err;
	}

	DEBUG(3,("reply_checkpath %s mode=%d\n", name, (int)SVAL(req->inbuf,smb_vwv0)));

	status = unix_convert(ctx, conn, name, False, &name, NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto path_err;
	}

	status = check_name(conn, name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3,("reply_checkpath: check_name of %s failed (%s)\n",name,nt_errstr(status)));
		goto path_err;
	}

	if (!VALID_STAT(sbuf) && (SMB_VFS_STAT(conn,name,&sbuf) != 0)) {
		DEBUG(3,("reply_checkpath: stat of %s failed (%s)\n",name,strerror(errno)));
		status = map_nt_error_from_unix(errno);
		goto path_err;
	}

	if (!S_ISDIR(sbuf.st_mode)) {
		reply_botherror(req, NT_STATUS_NOT_A_DIRECTORY,
				ERRDOS, ERRbadpath);
		END_PROFILE(SMBcheckpath);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBcheckpath);
	return;

  path_err:

	END_PROFILE(SMBcheckpath);

	/* We special case this - as when a Windows machine
		is parsing a path is steps through the components
		one at a time - if a component fails it expects
		ERRbadpath, not ERRbadfile.
	*/
	status = map_checkpath_error((char *)req->inbuf, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Windows returns different error codes if
		 * the parent directory is valid but not the
		 * last component - it returns NT_STATUS_OBJECT_NAME_NOT_FOUND
		 * for that case and NT_STATUS_OBJECT_PATH_NOT_FOUND
		 * if the path is invalid.
		 */
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpath);
		return;
	}

	reply_nterror(req, status);
}

/****************************************************************************
 Reply to a getatr.
****************************************************************************/

void reply_getatr(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *fname = NULL;
	SMB_STRUCT_STAT sbuf;
	int mode=0;
	SMB_OFF_T size=0;
	time_t mtime=0;
	char *p;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBgetatr);

	p = smb_buf(req->inbuf) + 1;
	p += srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname, p,
			     0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBgetatr);
		return;
	}

	status = resolve_dfspath(ctx, conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				&fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBgetatr);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBgetatr);
		return;
	}

	/* dos smetimes asks for a stat of "" - it returns a "hidden directory"
		under WfWg - weird! */
	if (*fname == '\0') {
		mode = aHIDDEN | aDIR;
		if (!CAN_WRITE(conn)) {
			mode |= aRONLY;
		}
		size = 0;
		mtime = 0;
	} else {
		status = unix_convert(ctx, conn, fname, False, &fname, NULL,&sbuf);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBgetatr);
			return;
		}
		status = check_name(conn, fname);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("reply_getatr: check_name of %s failed (%s)\n",fname,nt_errstr(status)));
			reply_nterror(req, status);
			END_PROFILE(SMBgetatr);
			return;
		}
		if (!VALID_STAT(sbuf) && (SMB_VFS_STAT(conn,fname,&sbuf) != 0)) {
			DEBUG(3,("reply_getatr: stat of %s failed (%s)\n",fname,strerror(errno)));
			reply_unixerror(req, ERRDOS,ERRbadfile);
			END_PROFILE(SMBgetatr);
			return;
		}

		mode = dos_mode(conn,fname,&sbuf);
		size = sbuf.st_size;
		mtime = sbuf.st_mtime;
		if (mode & aDIR) {
			size = 0;
		}
	}

	reply_outbuf(req, 10, 0);

	SSVAL(req->outbuf,smb_vwv0,mode);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime);
	}
	SIVAL(req->outbuf,smb_vwv3,(uint32)size);

	if (Protocol >= PROTOCOL_NT1) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
	}
  
	DEBUG(3,("reply_getatr: name=%s mode=%d size=%u\n", fname, mode, (unsigned int)size ) );

	END_PROFILE(SMBgetatr);
	return;
}

/****************************************************************************
 Reply to a setatr.
****************************************************************************/

void reply_setatr(struct smb_request *req)
{
	struct timespec ts[2];
	connection_struct *conn = req->conn;
	char *fname = NULL;
	int mode;
	time_t mtime;
	SMB_STRUCT_STAT sbuf;
	char *p;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBsetatr);

	ZERO_STRUCT(ts);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	p = smb_buf(req->inbuf) + 1;
	p += srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname, p,
				0, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsetatr);
		return;
	}

	status = resolve_dfspath(ctx, conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				&fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBsetatr);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBsetatr);
		return;
	}

	status = unix_convert(ctx, conn, fname, False, &fname, NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsetatr);
		return;
	}

	status = check_name(conn, fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsetatr);
		return;
	}

	if (fname[0] == '.' && fname[1] == '\0') {
		/*
		 * Not sure here is the right place to catch this
		 * condition. Might be moved to somewhere else later -- vl
		 */
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsetatr);
		return;
	}

	mode = SVAL(req->inbuf,smb_vwv0);
	mtime = srv_make_unix_date3(req->inbuf+smb_vwv1);

	ts[1] = convert_time_t_to_timespec(mtime);
	status = smb_set_file_time(conn, NULL, fname,
				   &sbuf, ts, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBsetatr);
		return;
	}

	if (mode != FILE_ATTRIBUTE_NORMAL) {
		if (VALID_STAT_OF_DIR(sbuf))
			mode |= aDIR;
		else
			mode &= ~aDIR;

		if (file_set_dosmode(conn,fname,mode,&sbuf,NULL,false) != 0) {
			reply_unixerror(req, ERRDOS, ERRnoaccess);
			END_PROFILE(SMBsetatr);
			return;
		}
	}

	reply_outbuf(req, 0, 0);
 
	DEBUG( 3, ( "setatr name=%s mode=%d\n", fname, mode ) );
  
	END_PROFILE(SMBsetatr);
	return;
}

/****************************************************************************
 Reply to a dskattr.
****************************************************************************/

void reply_dskattr(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	SMB_BIG_UINT dfree,dsize,bsize;
	START_PROFILE(SMBdskattr);

	if (get_dfree_info(conn,".",True,&bsize,&dfree,&dsize) == (SMB_BIG_UINT)-1) {
		reply_unixerror(req, ERRHRD, ERRgeneral);
		END_PROFILE(SMBdskattr);
		return;
	}

	reply_outbuf(req, 5, 0);
	
	if (Protocol <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers 

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (SMB_BIG_UINT)((total_space+63*512) / (64*512));
		dfree = (SMB_BIG_UINT)((free_space+63*512) / (64*512));
		
		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(req->outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(req->outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,bsize/512);
		SSVAL(req->outbuf,smb_vwv2,512);
		SSVAL(req->outbuf,smb_vwv3,dfree);
	}

	DEBUG(3,("dskattr dfree=%d\n", (unsigned int)dfree));

	END_PROFILE(SMBdskattr);
	return;
}

/****************************************************************************
 Reply to a search.
 Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/

void reply_search(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *mask = NULL;
	char *directory = NULL;
	char *fname = NULL;
	SMB_OFF_T size;
	uint32 mode;
	time_t date;
	uint32 dirtype;
	unsigned int numentries = 0;
	unsigned int maxentries = 0;
	bool finished = False;
	char *p;
	int status_len;
	char *path = NULL;
	char status[21];
	int dptr_num= -1;
	bool check_descend = False;
	bool expect_close = False;
	NTSTATUS nt_status;
	bool mask_contains_wcard = False;
	bool allow_long_path_components = (req->flags2 & FLAGS2_LONG_PATH_COMPONENTS) ? True : False;
	TALLOC_CTX *ctx = talloc_tos();
	bool ask_sharemode = lp_parm_bool(SNUM(conn), "smbd", "search ask sharemode", true);

	START_PROFILE(SMBsearch);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsearch);
		return;
	}

	if (lp_posix_pathnames()) {
		reply_unknown_new(req, CVAL(req->inbuf, smb_com));
		END_PROFILE(SMBsearch);
		return;
	}

	/* If we were called as SMBffirst then we must expect close. */
	if(CVAL(req->inbuf,smb_com) == SMBffirst) {
		expect_close = True;
	}

	reply_outbuf(req, 1, 3);
	maxentries = SVAL(req->inbuf,smb_vwv0);
	dirtype = SVAL(req->inbuf,smb_vwv1);
	p = smb_buf(req->inbuf) + 1;
	p += srvstr_get_path_wcard(ctx,
				(char *)req->inbuf,
				req->flags2,
				&path,
				p,
				0,
				STR_TERMINATE,
				&nt_status,
				&mask_contains_wcard);
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBsearch);
		return;
	}

	nt_status = resolve_dfspath_wcard(ctx, conn,
					  req->flags2 & FLAGS2_DFS_PATHNAMES,
					  path,
					  &path,
					  &mask_contains_wcard);
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBsearch);
			return;
		}
		reply_nterror(req, nt_status);
		END_PROFILE(SMBsearch);
		return;
	}

	p++;
	status_len = SVAL(p, 0);
	p += 2;

	/* dirtype &= ~aDIR; */

	if (status_len == 0) {
		SMB_STRUCT_STAT sbuf;

		nt_status = unix_convert(ctx, conn, path, True,
				&directory, NULL, &sbuf);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_nterror(req, nt_status);
			END_PROFILE(SMBsearch);
			return;
		}

		nt_status = check_name(conn, directory);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_nterror(req, nt_status);
			END_PROFILE(SMBsearch);
			return;
		}

		p = strrchr_m(directory,'/');
		if (!p) {
			mask = directory;
			directory = talloc_strdup(ctx,".");
			if (!directory) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBsearch);
				return;
			}
		} else {
			*p = 0;
			mask = p+1;
		}

		if (*directory == '\0') {
			directory = talloc_strdup(ctx,".");
			if (!directory) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBsearch);
				return;
			}
		}
		memset((char *)status,'\0',21);
		SCVAL(status,0,(dirtype & 0x1F));

		nt_status = dptr_create(conn,
					directory,
					True,
					expect_close,
					req->smbpid,
					mask,
					mask_contains_wcard,
					dirtype,
					&conn->dirptr);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_nterror(req, nt_status);
			END_PROFILE(SMBsearch);
			return;
		}
		dptr_num = dptr_dnum(conn->dirptr);
	} else {
		int status_dirtype;

		memcpy(status,p,21);
		status_dirtype = CVAL(status,0) & 0x1F;
		if (status_dirtype != (dirtype & 0x1F)) {
			dirtype = status_dirtype;
		}

		conn->dirptr = dptr_fetch(status+12,&dptr_num);
		if (!conn->dirptr) {
			goto SearchEmpty;
		}
		string_set(&conn->dirpath,dptr_path(dptr_num));
		mask = dptr_wcard(dptr_num);
		if (!mask) {
			goto SearchEmpty;
		}
		/*
		 * For a 'continue' search we have no string. So
		 * check from the initial saved string.
		 */
		mask_contains_wcard = ms_has_wild(mask);
		dirtype = dptr_attr(dptr_num);
	}

	DEBUG(4,("dptr_num is %d\n",dptr_num));

	if ((dirtype&0x1F) == aVOLID) {
		char buf[DIR_STRUCT_SIZE];
		memcpy(buf,status,21);
		if (!make_dir_struct(ctx,buf,"???????????",volume_label(SNUM(conn)),
				0,aVOLID,0,!allow_long_path_components)) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsearch);
			return;
		}
		dptr_fill(buf+12,dptr_num);
		if (dptr_zero(buf+12) && (status_len==0)) {
			numentries = 1;
		} else {
			numentries = 0;
		}
		if (message_push_blob(&req->outbuf,
				      data_blob_const(buf, sizeof(buf)))
		    == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsearch);
			return;
		}
	} else {
		unsigned int i;
		maxentries = MIN(
			maxentries,
			((BUFFER_SIZE -
			  ((uint8 *)smb_buf(req->outbuf) + 3 - req->outbuf))
			 /DIR_STRUCT_SIZE));

		DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
			conn->dirpath,lp_dontdescend(SNUM(conn))));
		if (in_list(conn->dirpath, lp_dontdescend(SNUM(conn)),True)) {
			check_descend = True;
		}

		for (i=numentries;(i<maxentries) && !finished;i++) {
			finished = !get_dir_entry(ctx,
						  conn,
						  mask,
						  dirtype,
						  &fname,
						  &size,
						  &mode,
						  &date,
						  check_descend,
						  ask_sharemode);
			if (!finished) {
				char buf[DIR_STRUCT_SIZE];
				memcpy(buf,status,21);
				if (!make_dir_struct(ctx,
						buf,
						mask,
						fname,
						size,
						mode,
						date,
						!allow_long_path_components)) {
					reply_nterror(req, NT_STATUS_NO_MEMORY);
					END_PROFILE(SMBsearch);
					return;
				}
				if (!dptr_fill(buf+12,dptr_num)) {
					break;
				}
				if (message_push_blob(&req->outbuf,
						      data_blob_const(buf, sizeof(buf)))
				    == -1) {
					reply_nterror(req, NT_STATUS_NO_MEMORY);
					END_PROFILE(SMBsearch);
					return;
				}
				numentries++;
			}
		}
	}

  SearchEmpty:

	/* If we were called as SMBffirst with smb_search_id == NULL
		and no entries were found then return error and close dirptr 
		(X/Open spec) */

	if (numentries == 0) {
		dptr_close(&dptr_num);
	} else if(expect_close && status_len == 0) {
		/* Close the dptr - we know it's gone */
		dptr_close(&dptr_num);
	}

	/* If we were called as SMBfunique, then we can close the dirptr now ! */
	if(dptr_num >= 0 && CVAL(req->inbuf,smb_com) == SMBfunique) {
		dptr_close(&dptr_num);
	}

	if ((numentries == 0) && !mask_contains_wcard) {
		reply_botherror(req, STATUS_NO_MORE_FILES, ERRDOS, ERRnofiles);
		END_PROFILE(SMBsearch);
		return;
	}

	SSVAL(req->outbuf,smb_vwv0,numentries);
	SSVAL(req->outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
	SCVAL(smb_buf(req->outbuf),0,5);
	SSVAL(smb_buf(req->outbuf),1,numentries*DIR_STRUCT_SIZE);

	/* The replies here are never long name. */
	SSVAL(req->outbuf, smb_flg2,
	      SVAL(req->outbuf, smb_flg2) & (~FLAGS2_IS_LONG_NAME));
	if (!allow_long_path_components) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2)
		      & (~FLAGS2_LONG_PATH_COMPONENTS));
	}

	/* This SMB *always* returns ASCII names. Remove the unicode bit in flags2. */
	SSVAL(req->outbuf, smb_flg2,
	      (SVAL(req->outbuf, smb_flg2) & (~FLAGS2_UNICODE_STRINGS)));

	if (!directory) {
		directory = dptr_path(dptr_num);
	}

	DEBUG(4,("%s mask=%s path=%s dtype=%d nument=%u of %u\n",
		smb_fn_name(CVAL(req->inbuf,smb_com)),
		mask,
		directory ? directory : "./",
		dirtype,
		numentries,
		maxentries ));

	END_PROFILE(SMBsearch);
	return;
}

/****************************************************************************
 Reply to a fclose (stop directory search).
****************************************************************************/

void reply_fclose(struct smb_request *req)
{
	int status_len;
	char status[21];
	int dptr_num= -2;
	char *p;
	char *path = NULL;
	NTSTATUS err;
	bool path_contains_wcard = False;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBfclose);

	if (lp_posix_pathnames()) {
		reply_unknown_new(req, CVAL(req->inbuf, smb_com));
		END_PROFILE(SMBfclose);
		return;
	}

	p = smb_buf(req->inbuf) + 1;
	p += srvstr_get_path_wcard(ctx,
				(char *)req->inbuf,
				req->flags2,
				&path,
				p,
				0,
				STR_TERMINATE,
				&err,
				&path_contains_wcard);
	if (!NT_STATUS_IS_OK(err)) {
		reply_nterror(req, err);
		END_PROFILE(SMBfclose);
		return;
	}
	p++;
	status_len = SVAL(p,0);
	p += 2;

	if (status_len == 0) {
		reply_doserror(req, ERRSRV, ERRsrverror);
		END_PROFILE(SMBfclose);
		return;
	}

	memcpy(status,p,21);

	if(dptr_fetch(status+12,&dptr_num)) {
		/*  Close the dptr - we know it's gone */
		dptr_close(&dptr_num);
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,0);

	DEBUG(3,("search close\n"));

	END_PROFILE(SMBfclose);
	return;
}

/****************************************************************************
 Reply to an open.
****************************************************************************/

void reply_open(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *fname = NULL;
	uint32 fattr=0;
	SMB_OFF_T size = 0;
	time_t mtime=0;
	int info;
	SMB_STRUCT_STAT sbuf;
	files_struct *fsp;
	int oplock_request;
	int deny_mode;
	uint32 dos_attr;
	uint32 access_mask;
	uint32 share_mode;
	uint32 create_disposition;
	uint32 create_options = 0;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBopen);
		return;
	}

	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	deny_mode = SVAL(req->inbuf,smb_vwv0);
	dos_attr = SVAL(req->inbuf,smb_vwv1);

	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname,
			smb_buf(req->inbuf)+1, 0,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBopen);
		return;
	}

	if (!map_open_params_to_ntcreate(
		    fname, deny_mode, OPENX_FILE_EXISTS_OPEN, &access_mask,
		    &share_mode, &create_disposition, &create_options)) {
		reply_nterror(req, NT_STATUS_DOS(ERRDOS, ERRbadaccess));
		END_PROFILE(SMBopen);
		return;
	}

	status = create_file(conn,			/* conn */
			     req,			/* req */
			     0,				/* root_dir_fid */
			     fname,			/* fname */
			     access_mask,		/* access_mask */
			     share_mode,		/* share_access */
			     create_disposition,	/* create_disposition*/
			     create_options,		/* create_options */
			     dos_attr,			/* file_attributes */
			     oplock_request,		/* oplock_request */
			     0,				/* allocation_size */
			     NULL,			/* sd */
			     NULL,			/* ea_list */
			     &fsp,			/* result */
			     &info,			/* pinfo */
			     &sbuf);			/* psbuf */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			END_PROFILE(SMBopen);
			return;
		}
		reply_openerror(req, status);
		END_PROFILE(SMBopen);
		return;
	}

	size = sbuf.st_size;
	fattr = dos_mode(conn,fsp->fsp_name,&sbuf);
	mtime = sbuf.st_mtime;

	if (fattr & aDIR) {
		DEBUG(3,("attempt to open a directory %s\n",fsp->fsp_name));
		close_file(fsp,ERROR_CLOSE);
		reply_doserror(req, ERRDOS,ERRnoaccess);
		END_PROFILE(SMBopen);
		return;
	}

	reply_outbuf(req, 7, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv1,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime);
	}
	SIVAL(req->outbuf,smb_vwv4,(uint32)size);
	SSVAL(req->outbuf,smb_vwv6,deny_mode);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
    
	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
	END_PROFILE(SMBopen);
	return;
}

/****************************************************************************
 Reply to an open and X.
****************************************************************************/

void reply_open_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *fname = NULL;
	uint16 open_flags;
	int deny_mode;
	uint32 smb_attr;
	/* Breakout the oplock request bits so we can set the
		reply bits separately. */
	int ex_oplock_request;
	int core_oplock_request;
	int oplock_request;
#if 0
	int smb_sattr = SVAL(req->inbuf,smb_vwv4);
	uint32 smb_time = make_unix_date3(req->inbuf+smb_vwv6);
#endif
	int smb_ofun;
	uint32 fattr=0;
	int mtime=0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	files_struct *fsp;
	NTSTATUS status;
	SMB_BIG_UINT allocation_size;
	ssize_t retval = -1;
	uint32 access_mask;
	uint32 share_mode;
	uint32 create_disposition;
	uint32 create_options = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopenX);

	if (req->wct < 15) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBopenX);
		return;
	}

	open_flags = SVAL(req->inbuf,smb_vwv2);
	deny_mode = SVAL(req->inbuf,smb_vwv3);
	smb_attr = SVAL(req->inbuf,smb_vwv5);
	ex_oplock_request = EXTENDED_OPLOCK_REQUEST(req->inbuf);
	core_oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	oplock_request = ex_oplock_request | core_oplock_request;
	smb_ofun = SVAL(req->inbuf,smb_vwv8);
	allocation_size = (SMB_BIG_UINT)IVAL(req->inbuf,smb_vwv9);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			reply_open_pipe_and_X(conn, req);
		} else {
			reply_doserror(req, ERRSRV, ERRaccess);
		}
		END_PROFILE(SMBopenX);
		return;
	}

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname,
			smb_buf(req->inbuf), 0, STR_TERMINATE,
			&status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBopenX);
		return;
	}

	if (!map_open_params_to_ntcreate(
		    fname, deny_mode, smb_ofun, &access_mask,
		    &share_mode, &create_disposition, &create_options)) {
		reply_nterror(req, NT_STATUS_DOS(ERRDOS, ERRbadaccess));
		END_PROFILE(SMBopenX);
		return;
	}

	status = create_file(conn,			/* conn */
			     req,			/* req */
			     0,				/* root_dir_fid */
			     fname,			/* fname */
			     access_mask,		/* access_mask */
			     share_mode,		/* share_access */
			     create_disposition,	/* create_disposition*/
			     create_options,		/* create_options */
			     smb_attr,			/* file_attributes */
			     oplock_request,		/* oplock_request */
			     0,				/* allocation_size */
			     NULL,			/* sd */
			     NULL,			/* ea_list */
			     &fsp,			/* result */
			     &smb_action,		/* pinfo */
			     &sbuf);			/* psbuf */

	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBopenX);
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			return;
		}
		reply_openerror(req, status);
		return;
	}

	/* Setting the "size" field in vwv9 and vwv10 causes the file to be set to this size,
	   if the file is truncated or created. */
	if (((smb_action == FILE_WAS_CREATED) || (smb_action == FILE_WAS_OVERWRITTEN)) && allocation_size) {
		fsp->initial_allocation_size = smb_roundup(fsp->conn, allocation_size);
		if (vfs_allocate_file_space(fsp, fsp->initial_allocation_size) == -1) {
			close_file(fsp,ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			END_PROFILE(SMBopenX);
			return;
		}
		retval = vfs_set_filelen(fsp, (SMB_OFF_T)allocation_size);
		if (retval < 0) {
			close_file(fsp,ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			END_PROFILE(SMBopenX);
			return;
		}
		sbuf.st_size = get_allocation_size(conn,fsp,&sbuf);
	}

	fattr = dos_mode(conn,fsp->fsp_name,&sbuf);
	mtime = sbuf.st_mtime;
	if (fattr & aDIR) {
		close_file(fsp,ERROR_CLOSE);
		reply_doserror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBopenX);
		return;
	}

	/* If the caller set the extended oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for extended oplock reply.
	*/

	if (ex_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	if(ex_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	/* If the caller set the core oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for core oplock reply.
	*/

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		reply_outbuf(req, 19, 0);
	} else {
		reply_outbuf(req, 15, 0);
	}

	if (core_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(core_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	SSVAL(req->outbuf,smb_vwv2,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv3,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime);
	}
	SIVAL(req->outbuf,smb_vwv6,(uint32)sbuf.st_size);
	SSVAL(req->outbuf,smb_vwv8,GET_OPENX_MODE(deny_mode));
	SSVAL(req->outbuf,smb_vwv11,smb_action);

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		SIVAL(req->outbuf, smb_vwv15, STD_RIGHT_ALL_ACCESS);
	}

	END_PROFILE(SMBopenX);
	chain_reply(req);
	return;
}

/****************************************************************************
 Reply to a SMBulogoffX.
****************************************************************************/

void reply_ulogoffX(struct smb_request *req)
{
	user_struct *vuser;

	START_PROFILE(SMBulogoffX);

	vuser = get_valid_user_struct(req->vuid);

	if(vuser == NULL) {
		DEBUG(3,("ulogoff, vuser id %d does not map to user.\n",
			 req->vuid));
	}

	/* in user level security we are supposed to close any files
		open by this user */
	if ((vuser != NULL) && (lp_security() != SEC_SHARE)) {
		file_close_user(req->vuid);
	}

	invalidate_vuid(req->vuid);

	reply_outbuf(req, 2, 0);

	DEBUG( 3, ( "ulogoffX vuid=%d\n", req->vuid ) );

	END_PROFILE(SMBulogoffX);
	chain_reply(req);
}

/****************************************************************************
 Reply to a mknew or a create.
****************************************************************************/

void reply_mknew(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *fname = NULL;
	int com;
	uint32 fattr = 0;
	struct timespec ts[2];
	files_struct *fsp;
	int oplock_request = 0;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;
	uint32 access_mask = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	uint32 share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
	uint32 create_disposition;
	uint32 create_options = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcreate);

        if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBcreate);
		return;
	}

	fattr = SVAL(req->inbuf,smb_vwv0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	com = SVAL(req->inbuf,smb_com);

	ts[1] =convert_time_t_to_timespec(
			srv_make_unix_date3(req->inbuf + smb_vwv1));
			/* mtime. */

	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname,
                        smb_buf(req->inbuf) + 1, 0,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBcreate);
		return;
	}

	if (fattr & aVOLID) {
		DEBUG(0,("Attempt to create file (%s) with volid set - "
			"please report this\n", fname));
	}

	if(com == SMBmknew) {
		/* We should fail if file exists. */
		create_disposition = FILE_CREATE;
	} else {
		/* Create if file doesn't exist, truncate if it does. */
		create_disposition = FILE_OVERWRITE_IF;
	}

	status = create_file(conn,			/* conn */
			     req,			/* req */
			     0,				/* root_dir_fid */
			     fname,			/* fname */
			     access_mask,		/* access_mask */
			     share_mode,		/* share_access */
			     create_disposition,	/* create_disposition*/
			     create_options,		/* create_options */
			     fattr,			/* file_attributes */
			     oplock_request,		/* oplock_request */
			     0,				/* allocation_size */
			     NULL,			/* sd */
			     NULL,			/* ea_list */
			     &fsp,			/* result */
			     NULL,			/* pinfo */
			     &sbuf);			/* psbuf */

	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcreate);
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			return;
		}
		reply_openerror(req, status);
		return;
	}

	ts[0] = get_atimespec(&sbuf); /* atime. */
	status = smb_set_file_time(conn, fsp, fsp->fsp_name, &sbuf, ts, true);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcreate);
		reply_openerror(req, status);
		return;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG( 2, ( "reply_mknew: file %s\n", fsp->fsp_name ) );
	DEBUG( 3, ( "reply_mknew %s fd=%d dmode=0x%x\n",
		    fsp->fsp_name, fsp->fh->fd, (unsigned int)fattr ) );

	END_PROFILE(SMBcreate);
	return;
}

/****************************************************************************
 Reply to a create temporary file.
****************************************************************************/

void reply_ctemp(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *fname = NULL;
	uint32 fattr;
	files_struct *fsp;
	int oplock_request;
	int tmpfd;
	SMB_STRUCT_STAT sbuf;
	char *s;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBctemp);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBctemp);
		return;
	}

	fattr = SVAL(req->inbuf,smb_vwv0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);

	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &fname,
			smb_buf(req->inbuf)+1, 0, STR_TERMINATE,
			&status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBctemp);
		return;
	}
	if (*fname) {
		fname = talloc_asprintf(ctx,
				"%s/TMXXXXXX",
				fname);
	} else {
		fname = talloc_strdup(ctx, "TMXXXXXX");
	}

	if (!fname) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBctemp);
		return;
	}

	status = resolve_dfspath(ctx, conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				&fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBctemp);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBctemp);
		return;
	}

	status = unix_convert(ctx, conn, fname, False, &fname, NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBctemp);
		return;
	}

	status = check_name(conn, fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBctemp);
		return;
	}

	tmpfd = smb_mkstemp(fname);
	if (tmpfd == -1) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBctemp);
		return;
	}

	SMB_VFS_STAT(conn,fname,&sbuf);

	/* We should fail if file does not exist. */
	status = open_file_ntcreate(conn, req, fname, &sbuf,
				FILE_GENERIC_READ | FILE_GENERIC_WRITE,
				FILE_SHARE_READ|FILE_SHARE_WRITE,
				FILE_OPEN,
				0,
				fattr,
				oplock_request,
				NULL, &fsp);

	/* close fd from smb_mkstemp() */
	close(tmpfd);

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			END_PROFILE(SMBctemp);
			return;
		}
		reply_openerror(req, status);
		END_PROFILE(SMBctemp);
		return;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	/* the returned filename is relative to the directory */
	s = strrchr_m(fsp->fsp_name, '/');
	if (!s) {
		s = fsp->fsp_name;
	} else {
		s++;
	}

#if 0
	/* Tested vs W2K3 - this doesn't seem to be here - null terminated filename is the only
	   thing in the byte section. JRA */
	SSVALS(p, 0, -1); /* what is this? not in spec */
#endif
	if (message_push_string(&req->outbuf, s, STR_ASCII|STR_TERMINATE)
	    == -1) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBctemp);
		return;
	}

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
  
	if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG( 2, ( "reply_ctemp: created temp file %s\n", fsp->fsp_name ) );
	DEBUG( 3, ( "reply_ctemp %s fd=%d umode=0%o\n", fsp->fsp_name,
		    fsp->fh->fd, (unsigned int)sbuf.st_mode ) );

	END_PROFILE(SMBctemp);
	return;
}

/*******************************************************************
 Check if a user is allowed to rename a file.
********************************************************************/

static NTSTATUS can_rename(connection_struct *conn, files_struct *fsp,
			   uint16 dirtype, SMB_STRUCT_STAT *pst)
{
	uint32 fmode;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	fmode = dos_mode(conn, fsp->fsp_name, pst);
	if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM)) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (S_ISDIR(pst->st_mode)) {
		if (fsp->posix_open) {
			return NT_STATUS_OK;
		}

		/* If no pathnames are open below this
		   directory, allow the rename. */

		if (file_find_subpath(fsp)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_OK;
	}

	if (fsp->access_mask & (DELETE_ACCESS|FILE_WRITE_ATTRIBUTES)) {
		return NT_STATUS_OK;
	}

	return NT_STATUS_ACCESS_DENIED;
}

/*******************************************************************
 * unlink a file with all relevant access checks
 *******************************************************************/

static NTSTATUS do_unlink(connection_struct *conn,
			struct smb_request *req,
			const char *fname,
			uint32 dirtype)
{
	SMB_STRUCT_STAT sbuf;
	uint32 fattr;
	files_struct *fsp;
	uint32 dirtype_orig = dirtype;
	NTSTATUS status;

	DEBUG(10,("do_unlink: %s, dirtype = %d\n", fname, dirtype ));

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if (SMB_VFS_LSTAT(conn,fname,&sbuf) != 0) {
		return map_nt_error_from_unix(errno);
	}

	fattr = dos_mode(conn,fname,&sbuf);

	if (dirtype & FILE_ATTRIBUTE_NORMAL) {
		dirtype = aDIR|aARCH|aRONLY;
	}

	dirtype &= (aDIR|aARCH|aRONLY|aHIDDEN|aSYSTEM);
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (!dir_check_ftype(conn, fattr, dirtype)) {
		if (fattr & aDIR) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (dirtype_orig & 0x8000) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

#if 0
	if ((fattr & dirtype) & FILE_ATTRIBUTE_DIRECTORY) {
                return NT_STATUS_FILE_IS_A_DIRECTORY;
        }

        if ((fattr & ~dirtype) & (FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) {
                return NT_STATUS_NO_SUCH_FILE;
        }

	if (dirtype & 0xFF00) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

	dirtype &= 0xFF;
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	/* Can't delete a directory. */
	if (fattr & aDIR) {
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}
#endif

#if 0 /* JRATEST */
	else if (dirtype & aDIR) /* Asked for a directory and it isn't. */
		return NT_STATUS_OBJECT_NAME_INVALID;
#endif /* JRATEST */

	/* Fix for bug #3035 from SATOH Fumiyasu <fumiyas@miraclelinux.com>

	  On a Windows share, a file with read-only dosmode can be opened with
	  DELETE_ACCESS. But on a Samba share (delete readonly = no), it
	  fails with NT_STATUS_CANNOT_DELETE error.

	  This semantic causes a problem that a user can not
	  rename a file with read-only dosmode on a Samba share
	  from a Windows command prompt (i.e. cmd.exe, but can rename
	  from Windows Explorer).
	*/

	if (!lp_delete_readonly(SNUM(conn))) {
		if (fattr & aRONLY) {
			return NT_STATUS_CANNOT_DELETE;
		}
	}

	/* On open checks the open itself will check the share mode, so
	   don't do it here as we'll get it wrong. */

	status = create_file_unixpath
		(conn,			/* conn */
		 req,			/* req */
		 fname,			/* fname */
		 DELETE_ACCESS,		/* access_mask */
		 FILE_SHARE_NONE,	/* share_access */
		 FILE_OPEN,		/* create_disposition*/
		 FILE_NON_DIRECTORY_FILE, /* create_options */
		 FILE_ATTRIBUTE_NORMAL,	/* file_attributes */
		 0,			/* oplock_request */
		 0,			/* allocation_size */
		 NULL,			/* sd */
		 NULL,			/* ea_list */
		 &fsp,			/* result */
		 NULL,			/* pinfo */
		 &sbuf);		/* psbuf */

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("create_file_unixpath failed: %s\n",
			   nt_errstr(status)));
		return status;
	}

	/* The set is across all open files on this dev/inode pair. */
	if (!set_delete_on_close(fsp, True, &conn->server_info->utok)) {
		close_file(fsp, NORMAL_CLOSE);
		return NT_STATUS_ACCESS_DENIED;
	}

	return close_file(fsp,NORMAL_CLOSE);
}

/****************************************************************************
 The guts of the unlink command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS unlink_internals(connection_struct *conn, struct smb_request *req,
			  uint32 dirtype, const char *name_in, bool has_wild)
{
	const char *directory = NULL;
	char *mask = NULL;
	char *name = NULL;
	char *p = NULL;
	int count=0;
	NTSTATUS status = NT_STATUS_OK;
	SMB_STRUCT_STAT sbuf;
	TALLOC_CTX *ctx = talloc_tos();

	status = unix_convert(ctx, conn, name_in, has_wild, &name, NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	p = strrchr_m(name,'/');
	if (!p) {
		directory = talloc_strdup(ctx, ".");
		if (!directory) {
			return NT_STATUS_NO_MEMORY;
		}
		mask = name;
	} else {
		*p = 0;
		directory = name;
		mask = p+1;
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!VALID_STAT(sbuf) && mangle_is_mangled(mask,conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx,
				mask,
				&new_mask,
				conn->params );
		if (new_mask) {
			mask = new_mask;
		}
	}

	if (!has_wild) {
		directory = talloc_asprintf(ctx,
				"%s/%s",
				directory,
				mask);
		if (!directory) {
			return NT_STATUS_NO_MEMORY;
		}
		if (dirtype == 0) {
			dirtype = FILE_ATTRIBUTE_NORMAL;
		}

		status = check_name(conn, directory);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = do_unlink(conn, req, directory, dirtype);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		count++;
	} else {
		struct smb_Dir *dir_hnd = NULL;
		long offset = 0;
		const char *dname;

		if ((dirtype & SAMBA_ATTRIBUTES_MASK) == aDIR) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}

		if (strequal(mask,"????????.???")) {
			mask[0] = '*';
			mask[1] = '\0';
		}

		status = check_name(conn, directory);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		dir_hnd = OpenDir(talloc_tos(), conn, directory, mask,
				  dirtype);
		if (dir_hnd == NULL) {
			return map_nt_error_from_unix(errno);
		}

		/* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
		   the pattern matches against the long name, otherwise the short name 
		   We don't implement this yet XXXX
		*/

		status = NT_STATUS_NO_SUCH_FILE;

		while ((dname = ReadDirName(dir_hnd, &offset))) {
			SMB_STRUCT_STAT st;
			char *fname = NULL;

			if (!is_visible_file(conn, directory, dname, &st, True)) {
				continue;
			}

			/* Quick check for "." and ".." */
			if (ISDOT(dname) || ISDOTDOT(dname)) {
				continue;
			}

			if(!mask_match(dname, mask, conn->case_sensitive)) {
				continue;
			}

			fname = talloc_asprintf(ctx, "%s/%s",
					directory,
					dname);
			if (!fname) {
				return NT_STATUS_NO_MEMORY;
			}

			status = check_name(conn, fname);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				return status;
			}

			status = do_unlink(conn, req, fname, dirtype);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(fname);
				continue;
			}

			count++;
			DEBUG(3,("unlink_internals: successful unlink [%s]\n",
				 fname));

			TALLOC_FREE(fname);
		}
		TALLOC_FREE(dir_hnd);
	}

	if (count == 0 && NT_STATUS_IS_OK(status) && errno != 0) {
		status = map_nt_error_from_unix(errno);
	}

	return status;
}

/****************************************************************************
 Reply to a unlink
****************************************************************************/

void reply_unlink(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	uint32 dirtype;
	NTSTATUS status;
	bool path_contains_wcard = False;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBunlink);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBunlink);
		return;
	}

	dirtype = SVAL(req->inbuf,smb_vwv0);

	srvstr_get_path_wcard(ctx, (char *)req->inbuf, req->flags2, &name,
			      smb_buf(req->inbuf) + 1, 0,
			      STR_TERMINATE, &status, &path_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBunlink);
		return;
	}

	status = resolve_dfspath_wcard(ctx, conn,
				       req->flags2 & FLAGS2_DFS_PATHNAMES,
				       name,
				       &name,
				       &path_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBunlink);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBunlink);
		return;
	}

	DEBUG(3,("reply_unlink : %s\n",name));

	status = unlink_internals(conn, req, dirtype, name,
				  path_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			END_PROFILE(SMBunlink);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBunlink);
		return;
	}

	reply_outbuf(req, 0, 0);
	END_PROFILE(SMBunlink);

	return;
}

/****************************************************************************
 Fail for readbraw.
****************************************************************************/

static void fail_readraw(void)
{
	const char *errstr = talloc_asprintf(talloc_tos(),
			"FAIL ! reply_readbraw: socket write fail (%s)",
			strerror(errno));
	if (!errstr) {
		errstr = "";
	}
	exit_server_cleanly(errstr);
}

/****************************************************************************
 Fake (read/write) sendfile. Returns -1 on read or write fail.
****************************************************************************/

static ssize_t fake_sendfile(files_struct *fsp, SMB_OFF_T startpos,
			     size_t nread)
{
	size_t bufsize;
	size_t tosend = nread;
	char *buf;

	if (nread == 0) {
		return 0;
	}

	bufsize = MIN(nread, 65536);

	if (!(buf = SMB_MALLOC_ARRAY(char, bufsize))) {
		return -1;
	}

	while (tosend > 0) {
		ssize_t ret;
		size_t cur_read;

		if (tosend > bufsize) {
			cur_read = bufsize;
		} else {
			cur_read = tosend;
		}
		ret = read_file(fsp,buf,startpos,cur_read);
		if (ret == -1) {
			SAFE_FREE(buf);
			return -1;
		}

		/* If we had a short read, fill with zeros. */
		if (ret < cur_read) {
			memset(buf, '\0', cur_read - ret);
		}

		if (write_data(smbd_server_fd(),buf,cur_read) != cur_read) {
			SAFE_FREE(buf);
			return -1;
		}
		tosend -= cur_read;
		startpos += cur_read;
	}

	SAFE_FREE(buf);
	return (ssize_t)nread;
}

/****************************************************************************
 Return a readbraw error (4 bytes of zero).
****************************************************************************/

static void reply_readbraw_error(void)
{
	char header[4];
	SIVAL(header,0,0);
	if (write_data(smbd_server_fd(),header,4) != 4) {
		fail_readraw();
	}
}

/****************************************************************************
 Use sendfile in readbraw.
****************************************************************************/

void send_file_readbraw(connection_struct *conn,
			files_struct *fsp,
			SMB_OFF_T startpos,
			size_t nread,
			ssize_t mincount)
{
	char *outbuf = NULL;
	ssize_t ret=0;

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet 
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 * reply_readbraw has already checked the length.
	 */

	if ( (chain_size == 0) && (nread > 0) && (fsp->base_fsp == NULL) &&
	    (fsp->wcp == NULL) && lp_use_sendfile(SNUM(conn)) ) {
		char header[4];
		DATA_BLOB header_blob;

		_smb_setlen(header,nread);
		header_blob = data_blob_const(header, 4);

		if (SMB_VFS_SENDFILE(smbd_server_fd(), fsp,
				&header_blob, startpos, nread) == -1) {
			/* Returning ENOSYS means no data at all was sent.
			 * Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_readbraw;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */
			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readbraw: sendfile not available. Faking..\n"));

				if (fake_sendfile(fsp, startpos, nread) == -1) {
					DEBUG(0,("send_file_readbraw: fake_sendfile failed for file %s (%s).\n",
						fsp->fsp_name, strerror(errno) ));
					exit_server_cleanly("send_file_readbraw fake_sendfile failed");
				}
				return;
			}

			DEBUG(0,("send_file_readbraw: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server_cleanly("send_file_readbraw sendfile failed");
		}

		return;
	}

normal_readbraw:
#endif

	outbuf = TALLOC_ARRAY(NULL, char, nread+4);
	if (!outbuf) {
		DEBUG(0,("send_file_readbraw: TALLOC_ARRAY failed for size %u.\n",
			(unsigned)(nread+4)));
		reply_readbraw_error();
		return;
	}

	if (nread > 0) {
		ret = read_file(fsp,outbuf+4,startpos,nread);
#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
		if (ret < mincount)
			ret = 0;
#else
		if (ret < nread)
			ret = 0;
#endif
	}

	_smb_setlen(outbuf,ret);
	if (write_data(smbd_server_fd(),outbuf,4+ret) != 4+ret)
		fail_readraw();

	TALLOC_FREE(outbuf);
}

/****************************************************************************
 Reply to a readbraw (core+ protocol).
****************************************************************************/

void reply_readbraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t maxcount,mincount;
	size_t nread = 0;
	SMB_OFF_T startpos;
	files_struct *fsp;
	SMB_STRUCT_STAT st;
	SMB_OFF_T size = 0;

	START_PROFILE(SMBreadbraw);

	if (srv_is_signing_active() || is_encrypted_packet(req->inbuf)) {
		exit_server_cleanly("reply_readbraw: SMB signing/sealing is active - "
			"raw reads/writes are disallowed.");
	}

	if (req->wct < 8) {
		reply_readbraw_error();
		END_PROFILE(SMBreadbraw);
		return;
	}

	/*
	 * Special check if an oplock break has been issued
	 * and the readraw request croses on the wire, we must
	 * return a zero length response here.
	 */

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	/*
	 * We have to do a check_fsp by hand here, as
	 * we must always return 4 zero bytes on error,
	 * not a NTSTATUS.
	 */

	if (!fsp || !conn || conn != fsp->conn ||
			req->vuid != fsp->vuid ||
			fsp->is_directory || fsp->fh->fd == -1) {
		/*
		 * fsp could be NULL here so use the value from the packet. JRA.
		 */
		DEBUG(3,("reply_readbraw: fnum %d not valid "
			"- cache prime?\n",
			(int)SVAL(req->inbuf,smb_vwv0)));
		reply_readbraw_error();
		END_PROFILE(SMBreadbraw);
		return;
	}

	/* Do a "by hand" version of CHECK_READ. */
	if (!(fsp->can_read ||
			((req->flags2 & FLAGS2_READ_PERMIT_EXECUTE) &&
				(fsp->access_mask & FILE_EXECUTE)))) {
		DEBUG(3,("reply_readbraw: fnum %d not readable.\n",
				(int)SVAL(req->inbuf,smb_vwv0)));
		reply_readbraw_error();
		END_PROFILE(SMBreadbraw);
		return;
	}

	flush_write_cache(fsp, READRAW_FLUSH);

	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv1);
	if(req->wct == 10) {
		/*
		 * This is a large offset (64 bit) read.
		 */
#ifdef LARGE_SMB_OFF_T

		startpos |= (((SMB_OFF_T)IVAL(req->inbuf,smb_vwv8)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(req->inbuf,smb_vwv8) != 0) {
			DEBUG(0,("reply_readbraw: large offset "
				"(%x << 32) used and we don't support "
				"64 bit offsets.\n",
			(unsigned int)IVAL(req->inbuf,smb_vwv8) ));
			reply_readbraw_error();
			END_PROFILE(SMBreadbraw);
			return;
		}

#endif /* LARGE_SMB_OFF_T */

		if(startpos < 0) {
			DEBUG(0,("reply_readbraw: negative 64 bit "
				"readraw offset (%.0f) !\n",
				(double)startpos ));
			reply_readbraw_error();
			END_PROFILE(SMBreadbraw);
			return;
		}      
	}

	maxcount = (SVAL(req->inbuf,smb_vwv3) & 0xFFFF);
	mincount = (SVAL(req->inbuf,smb_vwv4) & 0xFFFF);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535,maxcount);

	if (is_locked(fsp,(uint32)req->smbpid,
			(SMB_BIG_UINT)maxcount,
			(SMB_BIG_UINT)startpos,
			READ_LOCK)) {
		reply_readbraw_error();
		END_PROFILE(SMBreadbraw);
		return;
	}

	if (SMB_VFS_FSTAT(fsp, &st) == 0) {
		size = st.st_size;
	}

	if (startpos >= size) {
		nread = 0;
	} else {
		nread = MIN(maxcount,(size - startpos));
	}

#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
	if (nread < mincount)
		nread = 0;
#endif
  
	DEBUG( 3, ( "reply_readbraw: fnum=%d start=%.0f max=%lu "
		"min=%lu nread=%lu\n",
		fsp->fnum, (double)startpos,
		(unsigned long)maxcount,
		(unsigned long)mincount,
		(unsigned long)nread ) );
  
	send_file_readbraw(conn, fsp, startpos, nread, mincount);

	DEBUG(5,("reply_readbraw finished\n"));
	END_PROFILE(SMBreadbraw);
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lockread (core+ protocol).
****************************************************************************/

void reply_lockread(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t nread = -1;
	char *data;
	SMB_OFF_T startpos;
	size_t numtoread;
	NTSTATUS status;
	files_struct *fsp;
	struct byte_range_lock *br_lck = NULL;
	char *p = NULL;

	START_PROFILE(SMBlockread);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockread);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockread);
		return;
	}

	if (!CHECK_READ(fsp,req->inbuf)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		END_PROFILE(SMBlockread);
		return;
	}

	release_level_2_oplocks_on_change(fsp);

	numtoread = SVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv2);

	numtoread = MIN(BUFFER_SIZE - (smb_size + 3*2 + 3), numtoread);

	reply_outbuf(req, 5, numtoread + 3);

	data = smb_buf(req->outbuf) + 3;
	
	/*
	 * NB. Discovered by Menny Hamburger at Mainsoft. This is a core+
	 * protocol request that predates the read/write lock concept. 
	 * Thus instead of asking for a read lock here we need to ask
	 * for a write lock. JRA.
	 * Note that the requested lock size is unaffected by max_recv.
	 */
	
	br_lck = do_lock(smbd_messaging_context(),
			fsp,
			req->smbpid,
			(SMB_BIG_UINT)numtoread,
			(SMB_BIG_UINT)startpos,
			WRITE_LOCK,
			WINDOWS_LOCK,
			False, /* Non-blocking lock. */
			&status,
			NULL);
	TALLOC_FREE(br_lck);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBlockread);
		return;
	}

	/*
	 * However the requested READ size IS affected by max_recv. Insanity.... JRA.
	 */

	if (numtoread > max_recv) {
		DEBUG(0,("reply_lockread: requested read size (%u) is greater than maximum allowed (%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)max_recv ));
		numtoread = MIN(numtoread,max_recv);
	}
	nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBlockread);
		return;
	}
	
	srv_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	p = smb_buf(req->outbuf);
	SCVAL(p,0,0); /* pad byte. */
	SSVAL(p,1,nread);
	
	DEBUG(3,("lockread fnum=%d num=%d nread=%d\n",
		 fsp->fnum, (int)numtoread, (int)nread));

	END_PROFILE(SMBlockread);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a read.
****************************************************************************/

void reply_read(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtoread;
	ssize_t nread = 0;
	char *data;
	SMB_OFF_T startpos;
	int outsize = 0;
	files_struct *fsp;

	START_PROFILE(SMBread);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBread);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBread);
		return;
	}

	if (!CHECK_READ(fsp,req->inbuf)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		END_PROFILE(SMBread);
		return;
	}

	numtoread = SVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv2);

	numtoread = MIN(BUFFER_SIZE-outsize,numtoread);

	/*
	 * The requested read size cannot be greater than max_recv. JRA.
	 */
	if (numtoread > max_recv) {
		DEBUG(0,("reply_read: requested read size (%u) is greater than maximum allowed (%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)max_recv ));
		numtoread = MIN(numtoread,max_recv);
	}

	reply_outbuf(req, 5, numtoread+3);

	data = smb_buf(req->outbuf) + 3;
  
	if (is_locked(fsp, (uint32)req->smbpid, (SMB_BIG_UINT)numtoread,
		      (SMB_BIG_UINT)startpos, READ_LOCK)) {
		reply_doserror(req, ERRDOS,ERRlock);
		END_PROFILE(SMBread);
		return;
	}

	if (numtoread > 0)
		nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_unixerror(req, ERRDOS,ERRnoaccess);
		END_PROFILE(SMBread);
		return;
	}

	srv_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,nread);
  
	DEBUG( 3, ( "read fnum=%d num=%d nread=%d\n",
		fsp->fnum, (int)numtoread, (int)nread ) );

	END_PROFILE(SMBread);
	return;
}

/****************************************************************************
 Setup readX header.
****************************************************************************/

static int setup_readX_header(char *outbuf, size_t smb_maxcnt)
{
	int outsize;
	char *data;

	outsize = srv_set_message(outbuf,12,smb_maxcnt,False);
	data = smb_buf(outbuf);

	memset(outbuf+smb_vwv0,'\0',24); /* valgrind init. */

	SCVAL(outbuf,smb_vwv0,0xFF);
	SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
	SSVAL(outbuf,smb_vwv5,smb_maxcnt);
	SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
	SSVAL(outbuf,smb_vwv7,(smb_maxcnt >> 16));
	SSVAL(smb_buf(outbuf),-2,smb_maxcnt);
	/* Reset the outgoing length, set_message truncates at 0x1FFFF. */
	_smb_setlen_large(outbuf,(smb_size + 12*2 + smb_maxcnt - 4));
	return outsize;
}

/****************************************************************************
 Reply to a read and X - possibly using sendfile.
****************************************************************************/

static void send_file_readX(connection_struct *conn, struct smb_request *req,
			    files_struct *fsp, SMB_OFF_T startpos,
			    size_t smb_maxcnt)
{
	SMB_STRUCT_STAT sbuf;
	ssize_t nread = -1;

	if(SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		return;
	}

	if (startpos > sbuf.st_size) {
		smb_maxcnt = 0;
	} else if (smb_maxcnt > (sbuf.st_size - startpos)) {
		smb_maxcnt = (sbuf.st_size - startpos);
	}

	if (smb_maxcnt == 0) {
		goto normal_read;
	}

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 */

	if ((chain_size == 0) && (CVAL(req->inbuf,smb_vwv0) == 0xFF) &&
	    !is_encrypted_packet(req->inbuf) && (fsp->base_fsp == NULL) &&
	    lp_use_sendfile(SNUM(conn)) && (fsp->wcp == NULL) ) {
		uint8 headerbuf[smb_size + 12 * 2];
		DATA_BLOB header;

		/*
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		header = data_blob_const(headerbuf, sizeof(headerbuf));

		construct_reply_common((char *)req->inbuf, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		if ((nread = SMB_VFS_SENDFILE(smbd_server_fd(), fsp, &header, startpos, smb_maxcnt)) == -1) {
			/* Returning ENOSYS means no data at all was sent.
			   Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_read;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */

			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readX: sendfile not available. Faking..\n"));
				nread = fake_sendfile(fsp, startpos,
						      smb_maxcnt);
				if (nread == -1) {
					DEBUG(0,("send_file_readX: fake_sendfile failed for file %s (%s).\n",
						fsp->fsp_name, strerror(errno) ));
					exit_server_cleanly("send_file_readX: fake_sendfile failed");
				}
				DEBUG( 3, ( "send_file_readX: fake_sendfile fnum=%d max=%d nread=%d\n",
					fsp->fnum, (int)smb_maxcnt, (int)nread ) );
				/* No outbuf here means successful sendfile. */
				TALLOC_FREE(req->outbuf);
				return;
			}

			DEBUG(0,("send_file_readX: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server_cleanly("send_file_readX sendfile failed");
		}

		DEBUG( 3, ( "send_file_readX: sendfile fnum=%d max=%d nread=%d\n",
			fsp->fnum, (int)smb_maxcnt, (int)nread ) );
		/* No outbuf here means successful sendfile. */
		TALLOC_FREE(req->outbuf);
		return;
	}
#endif

normal_read:

	if ((smb_maxcnt & 0xFF0000) > 0x10000) {
		uint8 headerbuf[smb_size + 2*12];

		construct_reply_common((char *)req->inbuf, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		/* Send out the header. */
		if (write_data(smbd_server_fd(), (char *)headerbuf,
			       sizeof(headerbuf)) != sizeof(headerbuf)) {
			DEBUG(0,("send_file_readX: write_data failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server_cleanly("send_file_readX sendfile failed");
		}
		nread = fake_sendfile(fsp, startpos, smb_maxcnt);
		if (nread == -1) {
			DEBUG(0,("send_file_readX: fake_sendfile failed for file %s (%s).\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server_cleanly("send_file_readX: fake_sendfile failed");
		}
		TALLOC_FREE(req->outbuf);
		return;
	} else {
		reply_outbuf(req, 12, smb_maxcnt);

		nread = read_file(fsp, smb_buf(req->outbuf), startpos,
				  smb_maxcnt);
		if (nread < 0) {
			reply_unixerror(req, ERRDOS, ERRnoaccess);
			return;
		}

		setup_readX_header((char *)req->outbuf, nread);

		DEBUG( 3, ( "send_file_readX fnum=%d max=%d nread=%d\n",
			fsp->fnum, (int)smb_maxcnt, (int)nread ) );

		chain_reply(req);

		return;
	}
}

/****************************************************************************
 Reply to a read and X.
****************************************************************************/

void reply_read_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	SMB_OFF_T startpos;
	size_t smb_maxcnt;
	bool big_readX = False;
#if 0
	size_t smb_mincnt = SVAL(req->inbuf,smb_vwv6);
#endif

	START_PROFILE(SMBreadX);

	if ((req->wct != 10) && (req->wct != 12)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv2));
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv3);
	smb_maxcnt = SVAL(req->inbuf,smb_vwv5);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_read_and_X(req);
		END_PROFILE(SMBreadX);
		return;
	}

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBreadX);
		return;
	}

	if (!CHECK_READ(fsp,req->inbuf)) {
		reply_doserror(req, ERRDOS,ERRbadaccess);
		END_PROFILE(SMBreadX);
		return;
	}

	if (global_client_caps & CAP_LARGE_READX) {
		size_t upper_size = SVAL(req->inbuf,smb_vwv7);
		smb_maxcnt |= (upper_size<<16);
		if (upper_size > 1) {
			/* Can't do this on a chained packet. */
			if ((CVAL(req->inbuf,smb_vwv0) != 0xFF)) {
				reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
				END_PROFILE(SMBreadX);
				return;
			}
			/* We currently don't do this on signed or sealed data. */
			if (srv_is_signing_active() || is_encrypted_packet(req->inbuf)) {
				reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
				END_PROFILE(SMBreadX);
				return;
			}
			/* Is there room in the reply for this data ? */
			if (smb_maxcnt > (0xFFFFFF - (smb_size -4 + 12*2)))  {
				reply_nterror(req,
					      NT_STATUS_INVALID_PARAMETER);
				END_PROFILE(SMBreadX);
				return;
			}
			big_readX = True;
		}
	}

	if (req->wct == 12) {
#ifdef LARGE_SMB_OFF_T
		/*
		 * This is a large offset (64 bit) read.
		 */
		startpos |= (((SMB_OFF_T)IVAL(req->inbuf,smb_vwv10)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(req->inbuf,smb_vwv10) != 0) {
			DEBUG(0,("reply_read_and_X - large offset (%x << 32) "
				 "used and we don't support 64 bit offsets.\n",
				 (unsigned int)IVAL(req->inbuf,smb_vwv10) ));
			END_PROFILE(SMBreadX);
			reply_doserror(req, ERRDOS, ERRbadaccess);
			return;
		}

#endif /* LARGE_SMB_OFF_T */

	}

	if (is_locked(fsp, (uint32)req->smbpid, (SMB_BIG_UINT)smb_maxcnt,
		      (SMB_BIG_UINT)startpos, READ_LOCK)) {
		END_PROFILE(SMBreadX);
		reply_doserror(req, ERRDOS, ERRlock);
		return;
	}

	if (!big_readX &&
	    schedule_aio_read_and_X(conn, req, fsp, startpos, smb_maxcnt)) {
		END_PROFILE(SMBreadX);
		return;
	}

	send_file_readX(conn, req, fsp,	startpos, smb_maxcnt);

	END_PROFILE(SMBreadX);
	return;
}

/****************************************************************************
 Error replies to writebraw must have smb_wct == 1. Fix this up.
****************************************************************************/

void error_to_writebrawerr(struct smb_request *req)
{
	uint8 *old_outbuf = req->outbuf;

	reply_outbuf(req, 1, 0);

	memcpy(req->outbuf, old_outbuf, smb_size);
	TALLOC_FREE(old_outbuf);
}

/****************************************************************************
 Reply to a writebraw (core+ or LANMAN1.0 protocol).
****************************************************************************/

void reply_writebraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *buf = NULL;
	ssize_t nwritten=0;
	ssize_t total_written=0;
	size_t numtowrite=0;
	size_t tcount;
	SMB_OFF_T startpos;
	char *data=NULL;
	bool write_through;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBwritebraw);

	/*
	 * If we ever reply with an error, it must have the SMB command
	 * type of SMBwritec, not SMBwriteBraw, as this tells the client
	 * we're finished.
	 */
	SCVAL(req->inbuf,smb_com,SMBwritec);

	if (srv_is_signing_active()) {
		END_PROFILE(SMBwritebraw);
		exit_server_cleanly("reply_writebraw: SMB signing is active - "
				"raw reads/writes are disallowed.");
	}

	if (req->wct < 12) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));
	if (!check_fsp(conn, req, fsp)) {
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	tcount = IVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv3);
	write_through = BITSETW(req->inbuf+smb_vwv7,0);

	/* We have to deal with slightly different formats depending
		on whether we are using the core+ or lanman1.0 protocol */

	if(Protocol <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf(req->inbuf),-2);
		data = smb_buf(req->inbuf);
	} else {
		numtowrite = SVAL(req->inbuf,smb_vwv10);
		data = smb_base(req->inbuf) + SVAL(req->inbuf, smb_vwv11);
	}

	/* Ensure we don't write bytes past the end of this packet. */
	if (data + numtowrite > smb_base(req->inbuf) + smb_len(req->inbuf)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (is_locked(fsp,(uint32)req->smbpid,(SMB_BIG_UINT)tcount,
				(SMB_BIG_UINT)startpos, WRITE_LOCK)) {
		reply_doserror(req, ERRDOS, ERRlock);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (numtowrite>0) {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	DEBUG(3,("reply_writebraw: initial write fnum=%d start=%.0f num=%d "
			"wrote=%d sync=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite,
		(int)nwritten, (int)write_through));

	if (nwritten < (ssize_t)numtowrite)  {
		reply_unixerror(req, ERRHRD, ERRdiskfull);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	total_written = nwritten;

	/* Allocate a buffer of 64k + length. */
	buf = TALLOC_ARRAY(NULL, char, 65540);
	if (!buf) {
		reply_doserror(req, ERRDOS, ERRnomem);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	/* Return a SMBwritebraw message to the redirector to tell
	 * it to send more bytes */

	memcpy(buf, req->inbuf, smb_size);
	srv_set_message(buf,Protocol>PROTOCOL_COREPLUS?1:0,0,True);
	SCVAL(buf,smb_com,SMBwritebraw);
	SSVALS(buf,smb_vwv0,0xFFFF);
	show_msg(buf);
	if (!srv_send_smb(smbd_server_fd(),
			buf,
			IS_CONN_ENCRYPTED(conn))) {
		exit_server_cleanly("reply_writebraw: srv_send_smb "
			"failed.");
	}

	/* Now read the raw data into the buffer and write it */
	status = read_smb_length(smbd_server_fd(), buf, SMB_SECONDARY_WAIT,
				 &numtowrite);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("secondary writebraw failed");
	}

	/* Set up outbuf to return the correct size */
	reply_outbuf(req, 1, 0);

	if (numtowrite != 0) {

		if (numtowrite > 0xFFFF) {
			DEBUG(0,("reply_writebraw: Oversize secondary write "
				"raw requested (%u). Terminating\n",
				(unsigned int)numtowrite ));
			exit_server_cleanly("secondary writebraw failed");
		}

		if (tcount > nwritten+numtowrite) {
			DEBUG(3,("reply_writebraw: Client overestimated the "
				"write %d %d %d\n",
				(int)tcount,(int)nwritten,(int)numtowrite));
		}

		status = read_data(smbd_server_fd(), buf+4, numtowrite);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("reply_writebraw: Oversize secondary write "
				 "raw read failed (%s). Terminating\n",
				 nt_errstr(status)));
			exit_server_cleanly("secondary writebraw failed");
		}

		nwritten = write_file(req,fsp,buf+4,startpos+nwritten,numtowrite);
		if (nwritten == -1) {
			TALLOC_FREE(buf);
			reply_unixerror(req, ERRHRD, ERRdiskfull);
			error_to_writebrawerr(req);
			END_PROFILE(SMBwritebraw);
			return;
		}

		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(req->outbuf,smb_rcls,ERRHRD);
			SSVAL(req->outbuf,smb_err,ERRdiskfull);
		}

		if (nwritten > 0) {
			total_written += nwritten;
		}
 	}

	TALLOC_FREE(buf);
	SSVAL(req->outbuf,smb_vwv0,total_written);

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writebraw: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status) ));
		reply_nterror(req, status);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	DEBUG(3,("reply_writebraw: secondart write fnum=%d start=%.0f num=%d "
		"wrote=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite,
		(int)total_written));

	/* We won't return a status if write through is not selected - this
	 * follows what WfWg does */
	END_PROFILE(SMBwritebraw);

	if (!write_through && total_written==tcount) {

#if RABBIT_PELLET_FIX
		/*
		 * Fix for "rabbit pellet" mode, trigger an early TCP ack by
		 * sending a SMBkeepalive. Thanks to DaveCB at Sun for this.
		 * JRA.
		 */
		if (!send_keepalive(smbd_server_fd())) {
			exit_server_cleanly("reply_writebraw: send of "
				"keepalive failed");
		}
#endif
		TALLOC_FREE(req->outbuf);
	}
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a writeunlock (core+).
****************************************************************************/

void reply_writeunlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t nwritten = -1;
	size_t numtowrite;
	SMB_OFF_T startpos;
	char *data;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp;

	START_PROFILE(SMBwriteunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteunlock);
		return;
	}
	
	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteunlock);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS,ERRbadaccess);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	numtowrite = SVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv2);
	data = smb_buf(req->inbuf) + 3;
  
	if (numtowrite
	    && is_locked(fsp, (uint32)req->smbpid, (SMB_BIG_UINT)numtowrite,
			 (SMB_BIG_UINT)startpos, WRITE_LOCK)) {
		reply_doserror(req, ERRDOS, ERRlock);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	/* The special X/Open SMB protocol handling of
	   zero length writes is *NOT* done for
	   this call */
	if(numtowrite == 0) {
		nwritten = 0;
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}
  
	status = sync_file(conn, fsp, False /* write through */);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writeunlock: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status) ));
		reply_nterror(req, status);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	if(((nwritten < numtowrite) && (numtowrite != 0))||(nwritten < 0)) {
		reply_unixerror(req, ERRHRD, ERRdiskfull);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	if (numtowrite) {
		status = do_unlock(smbd_messaging_context(),
				fsp,
				req->smbpid,
				(SMB_BIG_UINT)numtowrite, 
				(SMB_BIG_UINT)startpos,
				WINDOWS_LOCK);

		if (NT_STATUS_V(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBwriteunlock);
			return;
		}
	}

	reply_outbuf(req, 1, 0);
	
	SSVAL(req->outbuf,smb_vwv0,nwritten);
	
	DEBUG(3,("writeunlock fnum=%d num=%d wrote=%d\n",
		 fsp->fnum, (int)numtowrite, (int)nwritten));
	
	END_PROFILE(SMBwriteunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a write.
****************************************************************************/

void reply_write(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	ssize_t nwritten = -1;
	SMB_OFF_T startpos;
	char *data;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBwrite);

	if (req->wct < 5) {
		END_PROFILE(SMBwrite);
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_write(req);
		END_PROFILE(SMBwrite);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwrite);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		END_PROFILE(SMBwrite);
		return;
	}

	numtowrite = SVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv2);
	data = smb_buf(req->inbuf) + 3;
  
	if (is_locked(fsp, (uint32)req->smbpid, (SMB_BIG_UINT)numtowrite,
		      (SMB_BIG_UINT)startpos, WRITE_LOCK)) {
		reply_doserror(req, ERRDOS, ERRlock);
		END_PROFILE(SMBwrite);
		return;
	}

	/*
	 * X/Open SMB protocol says that if smb_vwv1 is
	 * zero then the file size should be extended or
	 * truncated to the size given in smb_vwv[2-3].
	 */

	if(numtowrite == 0) {
		/*
		 * This is actually an allocate call, and set EOF. JRA.
		 */
		nwritten = vfs_allocate_file_space(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			END_PROFILE(SMBwrite);
			return;
		}
		nwritten = vfs_set_filelen(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			END_PROFILE(SMBwrite);
			return;
		}
		trigger_write_time_update_immediate(fsp);
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	status = sync_file(conn, fsp, False);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status) ));
		reply_nterror(req, status);
		END_PROFILE(SMBwrite);
		return;
	}

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		reply_unixerror(req, ERRHRD, ERRdiskfull);
		END_PROFILE(SMBwrite);
		return;
	}

	reply_outbuf(req, 1, 0);
  
	SSVAL(req->outbuf,smb_vwv0,nwritten);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(req->outbuf,smb_rcls,ERRHRD);
		SSVAL(req->outbuf,smb_err,ERRdiskfull);
	}
  
	DEBUG(3,("write fnum=%d num=%d wrote=%d\n", fsp->fnum, (int)numtowrite, (int)nwritten));

	END_PROFILE(SMBwrite);
	return;
}

/****************************************************************************
 Ensure a buffer is a valid writeX for recvfile purposes.
****************************************************************************/

#define STANDARD_WRITE_AND_X_HEADER_SIZE (smb_size - 4 + /* basic header */ \
						(2*14) + /* word count (including bcc) */ \
						1 /* pad byte */)

bool is_valid_writeX_buffer(const uint8_t *inbuf)
{
	size_t numtowrite;
	connection_struct *conn = NULL;
	unsigned int doff = 0;
	size_t len = smb_len_large(inbuf);

	if (is_encrypted_packet(inbuf)) {
		/* Can't do this on encrypted
		 * connections. */
		return false;
	}

	if (CVAL(inbuf,smb_com) != SMBwriteX) {
		return false;
	}

	if (CVAL(inbuf,smb_vwv0) != 0xFF ||
			CVAL(inbuf,smb_wct) != 14) {
		DEBUG(10,("is_valid_writeX_buffer: chained or "
			"invalid word length.\n"));
		return false;
	}

	conn = conn_find(SVAL(inbuf, smb_tid));
	if (conn == NULL) {
		DEBUG(10,("is_valid_writeX_buffer: bad tid\n"));
		return false;
	}
	if (IS_IPC(conn)) {
		DEBUG(10,("is_valid_writeX_buffer: IPC$ tid\n"));
		return false;
	}
	if (IS_PRINT(conn)) {
		DEBUG(10,("is_valid_writeX_buffer: printing tid\n"));
		return false;
	}
	doff = SVAL(inbuf,smb_vwv11);

	numtowrite = SVAL(inbuf,smb_vwv10);

	if (len > doff && len - doff > 0xFFFF) {
		numtowrite |= (((size_t)SVAL(inbuf,smb_vwv9))<<16);
	}

	if (numtowrite == 0) {
		DEBUG(10,("is_valid_writeX_buffer: zero write\n"));
		return false;
	}

	/* Ensure the sizes match up. */
	if (doff < STANDARD_WRITE_AND_X_HEADER_SIZE) {
		/* no pad byte...old smbclient :-( */
		DEBUG(10,("is_valid_writeX_buffer: small doff %u (min %u)\n",
			(unsigned int)doff,
			(unsigned int)STANDARD_WRITE_AND_X_HEADER_SIZE));
		return false;
	}

	if (len - doff != numtowrite) {
		DEBUG(10,("is_valid_writeX_buffer: doff mismatch "
			"len = %u, doff = %u, numtowrite = %u\n",
			(unsigned int)len,
			(unsigned int)doff,
			(unsigned int)numtowrite ));
		return false;
	}

	DEBUG(10,("is_valid_writeX_buffer: true "
		"len = %u, doff = %u, numtowrite = %u\n",
		(unsigned int)len,
		(unsigned int)doff,
		(unsigned int)numtowrite ));

	return true;
}

/****************************************************************************
 Reply to a write and X.
****************************************************************************/

void reply_write_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	SMB_OFF_T startpos;
	size_t numtowrite;
	bool write_through;
	ssize_t nwritten;
	unsigned int smb_doff;
	unsigned int smblen;
	char *data;
	NTSTATUS status;

	START_PROFILE(SMBwriteX);

	if ((req->wct != 12) && (req->wct != 14)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteX);
		return;
	}

	numtowrite = SVAL(req->inbuf,smb_vwv10);
	smb_doff = SVAL(req->inbuf,smb_vwv11);
	smblen = smb_len(req->inbuf);

	if (req->unread_bytes > 0xFFFF ||
			(smblen > smb_doff &&
				smblen - smb_doff > 0xFFFF)) {
		numtowrite |= (((size_t)SVAL(req->inbuf,smb_vwv9))<<16);
	}

	if (req->unread_bytes) {
		/* Can't do a recvfile write on IPC$ */
		if (IS_IPC(conn)) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			END_PROFILE(SMBwriteX);
			return;
		}
	       	if (numtowrite != req->unread_bytes) {
			reply_doserror(req, ERRDOS, ERRbadmem);
			END_PROFILE(SMBwriteX);
			return;
		}
	} else {
		if (smb_doff > smblen || smb_doff + numtowrite < numtowrite ||
				smb_doff + numtowrite > smblen) {
			reply_doserror(req, ERRDOS, ERRbadmem);
			END_PROFILE(SMBwriteX);
			return;
		}
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (req->unread_bytes) {
			reply_doserror(req, ERRDOS, ERRbadmem);
			END_PROFILE(SMBwriteX);
			return;
		}
		reply_pipe_write_and_X(req);
		END_PROFILE(SMBwriteX);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv2));
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv3);
	write_through = BITSETW(req->inbuf+smb_vwv7,0);

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteX);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		END_PROFILE(SMBwriteX);
		return;
	}

	data = smb_base(req->inbuf) + smb_doff;

	if(req->wct == 14) {
#ifdef LARGE_SMB_OFF_T
		/*
		 * This is a large offset (64 bit) write.
		 */
		startpos |= (((SMB_OFF_T)IVAL(req->inbuf,smb_vwv12)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(req->inbuf,smb_vwv12) != 0) {
			DEBUG(0,("reply_write_and_X - large offset (%x << 32) "
				 "used and we don't support 64 bit offsets.\n",
				 (unsigned int)IVAL(req->inbuf,smb_vwv12) ));
			reply_doserror(req, ERRDOS, ERRbadaccess);
			END_PROFILE(SMBwriteX);
			return;
		}

#endif /* LARGE_SMB_OFF_T */
	}

	if (is_locked(fsp,(uint32)req->smbpid,
		      (SMB_BIG_UINT)numtowrite,
		      (SMB_BIG_UINT)startpos, WRITE_LOCK)) {
		reply_doserror(req, ERRDOS, ERRlock);
		END_PROFILE(SMBwriteX);
		return;
	}

	/* X/Open SMB protocol says that, unlike SMBwrite
	if the length is zero then NO truncation is
	done, just a write of zero. To truncate a file,
	use SMBwrite. */

	if(numtowrite == 0) {
		nwritten = 0;
	} else {

		if ((req->unread_bytes == 0) &&
		    schedule_aio_write_and_X(conn, req, fsp, data, startpos,
					     numtowrite)) {
			END_PROFILE(SMBwriteX);
			return;
		}
		
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		reply_unixerror(req, ERRHRD, ERRdiskfull);
		END_PROFILE(SMBwriteX);
		return;
	}

	reply_outbuf(req, 6, 0);
	SSVAL(req->outbuf,smb_vwv2,nwritten);
	SSVAL(req->outbuf,smb_vwv4,nwritten>>16);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(req->outbuf,smb_rcls,ERRHRD);
		SSVAL(req->outbuf,smb_err,ERRdiskfull);
	}

	DEBUG(3,("writeX fnum=%d num=%d wrote=%d\n",
		fsp->fnum, (int)numtowrite, (int)nwritten));

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write_and_X: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status) ));
		reply_nterror(req, status);
		END_PROFILE(SMBwriteX);
		return;
	}

	END_PROFILE(SMBwriteX);
	chain_reply(req);
	return;
}

/****************************************************************************
 Reply to a lseek.
****************************************************************************/

void reply_lseek(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	SMB_OFF_T startpos;
	SMB_OFF_T res= -1;
	int mode,umode;
	files_struct *fsp;

	START_PROFILE(SMBlseek);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlseek);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		return;
	}

	flush_write_cache(fsp, SEEK_FLUSH);

	mode = SVAL(req->inbuf,smb_vwv1) & 3;
	/* NB. This doesn't use IVAL_TO_SMB_OFF_T as startpos can be signed in this case. */
	startpos = (SMB_OFF_T)IVALS(req->inbuf,smb_vwv2);

	switch (mode) {
		case 0:
			umode = SEEK_SET;
			res = startpos;
			break;
		case 1:
			umode = SEEK_CUR;
			res = fsp->fh->pos + startpos;
			break;
		case 2:
			umode = SEEK_END;
			break;
		default:
			umode = SEEK_SET;
			res = startpos;
			break;
	}

	if (umode == SEEK_END) {
		if((res = SMB_VFS_LSEEK(fsp,startpos,umode)) == -1) {
			if(errno == EINVAL) {
				SMB_OFF_T current_pos = startpos;
				SMB_STRUCT_STAT sbuf;

				if(SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
					reply_unixerror(req, ERRDOS,
							ERRnoaccess);
					END_PROFILE(SMBlseek);
					return;
				}

				current_pos += sbuf.st_size;
				if(current_pos < 0)
					res = SMB_VFS_LSEEK(fsp,0,SEEK_SET);
			}
		}

		if(res == -1) {
			reply_unixerror(req, ERRDOS, ERRnoaccess);
			END_PROFILE(SMBlseek);
			return;
		}
	}

	fsp->fh->pos = res;

	reply_outbuf(req, 2, 0);
	SIVAL(req->outbuf,smb_vwv0,res);
  
	DEBUG(3,("lseek fnum=%d ofs=%.0f newpos = %.0f mode=%d\n",
		fsp->fnum, (double)startpos, (double)res, mode));

	END_PROFILE(SMBlseek);
	return;
}

/****************************************************************************
 Reply to a flush.
****************************************************************************/

void reply_flush(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint16 fnum;
	files_struct *fsp;

	START_PROFILE(SMBflush);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fnum = SVAL(req->inbuf,smb_vwv0);
	fsp = file_fsp(fnum);

	if ((fnum != 0xFFFF) && !check_fsp(conn, req, fsp)) {
		return;
	}
	
	if (!fsp) {
		file_sync_all(conn);
	} else {
		NTSTATUS status = sync_file(conn, fsp, True);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("reply_flush: sync_file for %s returned %s\n",
				fsp->fsp_name, nt_errstr(status) ));
			reply_nterror(req, status);
			END_PROFILE(SMBflush);
			return;
		}
	}
	
	reply_outbuf(req, 0, 0);

	DEBUG(3,("flush\n"));
	END_PROFILE(SMBflush);
	return;
}

/****************************************************************************
 Reply to a exit.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_exit(struct smb_request *req)
{
	START_PROFILE(SMBexit);

	file_close_pid(req->smbpid, req->vuid);

	reply_outbuf(req, 0, 0);

	DEBUG(3,("exit\n"));

	END_PROFILE(SMBexit);
	return;
}

/****************************************************************************
 Reply to a close - has to deal with closing a directory opened by NT SMB's.
****************************************************************************/

void reply_close(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp = NULL;
	START_PROFILE(SMBclose);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBclose);
		return;
	}

	/* If it's an IPC, pass off to the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_close(conn, req);
		END_PROFILE(SMBclose);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	/*
	 * We can only use check_fsp if we know it's not a directory.
	 */

	if(!fsp || (fsp->conn != conn) || (fsp->vuid != req->vuid)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		END_PROFILE(SMBclose);
		return;
	}

	if(fsp->is_directory) {
		/*
		 * Special case - close NT SMB directory handle.
		 */
		DEBUG(3,("close directory fnum=%d\n", fsp->fnum));
		status = close_file(fsp,NORMAL_CLOSE);
	} else {
		time_t t;
		/*
		 * Close ordinary file.
		 */

		DEBUG(3,("close fd=%d fnum=%d (numopen=%d)\n",
			 fsp->fh->fd, fsp->fnum,
			 conn->num_files_open));
 
		/*
		 * Take care of any time sent in the close.
		 */

		t = srv_make_unix_date3(req->inbuf+smb_vwv1);
		set_close_write_time(fsp, convert_time_t_to_timespec(t));

		/*
		 * close_file() returns the unix errno if an error
		 * was detected on close - normally this is due to
		 * a disk full error. If not then it was probably an I/O error.
		 */
 
		status = close_file(fsp,NORMAL_CLOSE);
	}  

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBclose);
		return;
	}

	reply_outbuf(req, 0, 0);
	END_PROFILE(SMBclose);
	return;
}

/****************************************************************************
 Reply to a writeclose (Core+ protocol).
****************************************************************************/

void reply_writeclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	ssize_t nwritten = -1;
	NTSTATUS close_status = NT_STATUS_OK;
	SMB_OFF_T startpos;
	char *data;
	struct timespec mtime;
	files_struct *fsp;

	START_PROFILE(SMBwriteclose);

	if (req->wct < 6) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteclose);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteclose);
		return;
	}
	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS,ERRbadaccess);
		END_PROFILE(SMBwriteclose);
		return;
	}

	numtowrite = SVAL(req->inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(req->inbuf,smb_vwv2);
	mtime = convert_time_t_to_timespec(srv_make_unix_date3(
						   req->inbuf+smb_vwv4));
	data = smb_buf(req->inbuf) + 1;
  
	if (numtowrite
	    && is_locked(fsp, (uint32)req->smbpid, (SMB_BIG_UINT)numtowrite,
			 (SMB_BIG_UINT)startpos, WRITE_LOCK)) {
		reply_doserror(req, ERRDOS,ERRlock);
		END_PROFILE(SMBwriteclose);
		return;
	}
  
	nwritten = write_file(req,fsp,data,startpos,numtowrite);

	set_close_write_time(fsp, mtime);

	/*
	 * More insanity. W2K only closes the file if writelen > 0.
	 * JRA.
	 */

	if (numtowrite) {
		DEBUG(3,("reply_writeclose: zero length write doesn't close file %s\n",
			fsp->fsp_name ));
		close_status = close_file(fsp,NORMAL_CLOSE);
	}

	DEBUG(3,("writeclose fnum=%d num=%d wrote=%d (numopen=%d)\n",
		 fsp->fnum, (int)numtowrite, (int)nwritten,
		 conn->num_files_open));
  
	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		reply_doserror(req, ERRHRD, ERRdiskfull);
		END_PROFILE(SMBwriteclose);
		return;
	}
 
	if(!NT_STATUS_IS_OK(close_status)) {
		reply_nterror(req, close_status);
		END_PROFILE(SMBwriteclose);
		return;
	}

	reply_outbuf(req, 1, 0);
  
	SSVAL(req->outbuf,smb_vwv0,nwritten);
	END_PROFILE(SMBwriteclose);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lock.
****************************************************************************/

void reply_lock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	SMB_BIG_UINT count,offset;
	NTSTATUS status;
	files_struct *fsp;
	struct byte_range_lock *br_lck = NULL;

	START_PROFILE(SMBlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlock);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlock);
		return;
	}

	release_level_2_oplocks_on_change(fsp);

	count = (SMB_BIG_UINT)IVAL(req->inbuf,smb_vwv1);
	offset = (SMB_BIG_UINT)IVAL(req->inbuf,smb_vwv3);

	DEBUG(3,("lock fd=%d fnum=%d offset=%.0f count=%.0f\n",
		 fsp->fh->fd, fsp->fnum, (double)offset, (double)count));

	br_lck = do_lock(smbd_messaging_context(),
			fsp,
			req->smbpid,
			count,
			offset,
			WRITE_LOCK,
			WINDOWS_LOCK,
			False, /* Non-blocking lock. */
			&status,
			NULL);

	TALLOC_FREE(br_lck);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBlock);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBlock);
	return;
}

/****************************************************************************
 Reply to a unlock.
****************************************************************************/

void reply_unlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	SMB_BIG_UINT count,offset;
	NTSTATUS status;
	files_struct *fsp;

	START_PROFILE(SMBunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBunlock);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBunlock);
		return;
	}
	
	count = (SMB_BIG_UINT)IVAL(req->inbuf,smb_vwv1);
	offset = (SMB_BIG_UINT)IVAL(req->inbuf,smb_vwv3);
	
	status = do_unlock(smbd_messaging_context(),
			fsp,
			req->smbpid,
			count,
			offset,
			WINDOWS_LOCK);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBunlock);
		return;
	}

	DEBUG( 3, ( "unlock fd=%d fnum=%d offset=%.0f count=%.0f\n",
		    fsp->fh->fd, fsp->fnum, (double)offset, (double)count ) );

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a tdis.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tdis(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	START_PROFILE(SMBtdis);

	if (!conn) {
		DEBUG(4,("Invalid connection in tdis\n"));
		reply_doserror(req, ERRSRV, ERRinvnid);
		END_PROFILE(SMBtdis);
		return;
	}

	conn->used = False;

	close_cnum(conn,req->vuid);
	req->conn = NULL;

	reply_outbuf(req, 0, 0);
	END_PROFILE(SMBtdis);
	return;
}

/****************************************************************************
 Reply to a echo.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_echo(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int smb_reverb;
	int seq_num;
	unsigned int data_len = smb_buflen(req->inbuf);

	START_PROFILE(SMBecho);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBecho);
		return;
	}

	if (data_len > BUFFER_SIZE) {
		DEBUG(0,("reply_echo: data_len too large.\n"));
		reply_nterror(req, NT_STATUS_INSUFFICIENT_RESOURCES);
		END_PROFILE(SMBecho);
		return;
	}

	smb_reverb = SVAL(req->inbuf,smb_vwv0);

	reply_outbuf(req, 1, data_len);

	/* copy any incoming data back out */
	if (data_len > 0) {
		memcpy(smb_buf(req->outbuf),smb_buf(req->inbuf),data_len);
	}

	if (smb_reverb > 100) {
		DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
		smb_reverb = 100;
	}

	for (seq_num =1 ; seq_num <= smb_reverb ; seq_num++) {
		SSVAL(req->outbuf,smb_vwv0,seq_num);

		show_msg((char *)req->outbuf);
		if (!srv_send_smb(smbd_server_fd(),
				(char *)req->outbuf,
				IS_CONN_ENCRYPTED(conn)||req->encrypted))
			exit_server_cleanly("reply_echo: srv_send_smb failed.");
	}

	DEBUG(3,("echo %d times\n", smb_reverb));

	TALLOC_FREE(req->outbuf);

	END_PROFILE(SMBecho);
	return;
}

/****************************************************************************
 Reply to a printopen.
****************************************************************************/

void reply_printopen(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;

	START_PROFILE(SMBsplopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplopen);
		return;
	}

	if (!CAN_PRINT(conn)) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBsplopen);
		return;
	}

	status = file_new(conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	/* Open for exclusive use, write only. */
	status = print_fsp_open(conn, NULL, req->vuid, fsp, &sbuf);

	if (!NT_STATUS_IS_OK(status)) {
		file_free(fsp);
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	DEBUG(3,("openprint fd=%d fnum=%d\n",
		 fsp->fh->fd, fsp->fnum));

	END_PROFILE(SMBsplopen);
	return;
}

/****************************************************************************
 Reply to a printclose.
****************************************************************************/

void reply_printclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplclose);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplclose);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplclose);
                return;
        }

	if (!CAN_PRINT(conn)) {
		reply_nterror(req, NT_STATUS_DOS(ERRSRV, ERRerror));
		END_PROFILE(SMBsplclose);
		return;
	}
  
	DEBUG(3,("printclose fd=%d fnum=%d\n",
		 fsp->fh->fd,fsp->fnum));
  
	status = close_file(fsp,NORMAL_CLOSE);

	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplclose);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBsplclose);
	return;
}

/****************************************************************************
 Reply to a printqueue.
****************************************************************************/

void reply_printqueue(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int max_count;
	int start_index;

	START_PROFILE(SMBsplretq);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplretq);
		return;
	}

	max_count = SVAL(req->inbuf,smb_vwv0);
	start_index = SVAL(req->inbuf,smb_vwv1);

	/* we used to allow the client to get the cnum wrong, but that
	   is really quite gross and only worked when there was only
	   one printer - I think we should now only accept it if they
	   get it right (tridge) */
	if (!CAN_PRINT(conn)) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBsplretq);
		return;
	}

	reply_outbuf(req, 2, 3);
	SSVAL(req->outbuf,smb_vwv0,0);
	SSVAL(req->outbuf,smb_vwv1,0);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,0);
  
	DEBUG(3,("printqueue start_index=%d max_count=%d\n",
		 start_index, max_count));

	{
		print_queue_struct *queue = NULL;
		print_status_struct status;
		int count = print_queue_status(SNUM(conn), &queue, &status);
		int num_to_get = ABS(max_count);
		int first = (max_count>0?start_index:start_index+max_count+1);
		int i;

		if (first >= count)
			num_to_get = 0;
		else
			num_to_get = MIN(num_to_get,count-first);
    

		for (i=first;i<first+num_to_get;i++) {
			char blob[28];
			char *p = blob;

			srv_put_dos_date2(p,0,queue[i].time);
			SCVAL(p,4,(queue[i].status==LPQ_PRINTING?2:3));
			SSVAL(p,5, queue[i].job);
			SIVAL(p,7,queue[i].size);
			SCVAL(p,11,0);
			srvstr_push(blob, req->flags2, p+12,
				    queue[i].fs_user, 16, STR_ASCII);

			if (message_push_blob(
				    &req->outbuf,
				    data_blob_const(
					    blob, sizeof(blob))) == -1) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBsplretq);
				return;
			}
		}

		if (count > 0) {
			SSVAL(req->outbuf,smb_vwv0,count);
			SSVAL(req->outbuf,smb_vwv1,
			      (max_count>0?first+count:first-1));
			SCVAL(smb_buf(req->outbuf),0,1);
			SSVAL(smb_buf(req->outbuf),1,28*count);
		}

		SAFE_FREE(queue);
	  
		DEBUG(3,("%d entries returned in queue\n",count));
	}
  
	END_PROFILE(SMBsplretq);
	return;
}

/****************************************************************************
 Reply to a printwrite.
****************************************************************************/

void reply_printwrite(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int numtowrite;
	char *data;
	files_struct *fsp;

	START_PROFILE(SMBsplwr);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}
  
	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplwr);
                return;
        }

	if (!CAN_PRINT(conn)) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBsplwr);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadaccess);
		END_PROFILE(SMBsplwr);
		return;
	}

	numtowrite = SVAL(smb_buf(req->inbuf),1);

	if (smb_buflen(req->inbuf) < numtowrite + 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}

	data = smb_buf(req->inbuf) + 3;

	if (write_file(req,fsp,data,-1,numtowrite) != numtowrite) {
		reply_unixerror(req, ERRHRD, ERRdiskfull);
		END_PROFILE(SMBsplwr);
		return;
	}

	DEBUG( 3, ( "printwrite fnum=%d num=%d\n", fsp->fnum, numtowrite ) );

	END_PROFILE(SMBsplwr);
	return;
}

/****************************************************************************
 Reply to a mkdir.
****************************************************************************/

void reply_mkdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *directory = NULL;
	NTSTATUS status;
	SMB_STRUCT_STAT sbuf;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBmkdir);

	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &directory,
			smb_buf(req->inbuf) + 1, 0,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBmkdir);
		return;
	}

	status = resolve_dfspath(ctx, conn,
				 req->flags2 & FLAGS2_DFS_PATHNAMES,
				 directory,
				 &directory);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBmkdir);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBmkdir);
		return;
	}

	status = unix_convert(ctx, conn, directory, False, &directory, NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBmkdir);
		return;
	}

	status = check_name(conn, directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBmkdir);
		return;
	}

	status = create_directory(conn, req, directory);

	DEBUG(5, ("create_directory returned %s\n", nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {

		if (!use_nt_status()
		    && NT_STATUS_EQUAL(status,
				       NT_STATUS_OBJECT_NAME_COLLISION)) {
			/*
			 * Yes, in the DOS error code case we get a
			 * ERRDOS:ERRnoaccess here. See BASE-SAMBA3ERROR
			 * samba4 torture test.
			 */
			status = NT_STATUS_DOS(ERRDOS, ERRnoaccess);
		}

		reply_nterror(req, status);
		END_PROFILE(SMBmkdir);
		return;
	}

	reply_outbuf(req, 0, 0);

	DEBUG( 3, ( "mkdir %s\n", directory ) );

	END_PROFILE(SMBmkdir);
	return;
}

/****************************************************************************
 Static function used by reply_rmdir to delete an entire directory
 tree recursively. Return True on ok, False on fail.
****************************************************************************/

static bool recursive_rmdir(TALLOC_CTX *ctx,
			connection_struct *conn,
			char *directory)
{
	const char *dname = NULL;
	bool ret = True;
	long offset = 0;
	struct smb_Dir *dir_hnd = OpenDir(talloc_tos(), conn, directory,
					  NULL, 0);

	if(dir_hnd == NULL)
		return False;

	while((dname = ReadDirName(dir_hnd, &offset))) {
		char *fullname = NULL;
		SMB_STRUCT_STAT st;

		if (ISDOT(dname) || ISDOTDOT(dname)) {
			continue;
		}

		if (!is_visible_file(conn, directory, dname, &st, False)) {
			continue;
		}

		/* Construct the full name. */
		fullname = talloc_asprintf(ctx,
				"%s/%s",
				directory,
				dname);
		if (!fullname) {
			errno = ENOMEM;
			ret = False;
			break;
		}

		if(SMB_VFS_LSTAT(conn,fullname, &st) != 0) {
			ret = False;
			break;
		}

		if(st.st_mode & S_IFDIR) {
			if(!recursive_rmdir(ctx, conn, fullname)) {
				ret = False;
				break;
			}
			if(SMB_VFS_RMDIR(conn,fullname) != 0) {
				ret = False;
				break;
			}
		} else if(SMB_VFS_UNLINK(conn,fullname) != 0) {
			ret = False;
			break;
		}
		TALLOC_FREE(fullname);
	}
	TALLOC_FREE(dir_hnd);
	return ret;
}

/****************************************************************************
 The internals of the rmdir code - called elsewhere.
****************************************************************************/

NTSTATUS rmdir_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *directory)
{
	int ret;
	SMB_STRUCT_STAT st;

	/* Might be a symlink. */
	if(SMB_VFS_LSTAT(conn, directory, &st) != 0) {
		return map_nt_error_from_unix(errno);
	}

	if (S_ISLNK(st.st_mode)) {
		/* Is what it points to a directory ? */
		if(SMB_VFS_STAT(conn, directory, &st) != 0) {
			return map_nt_error_from_unix(errno);
		}
		if (!(S_ISDIR(st.st_mode))) {
			return NT_STATUS_NOT_A_DIRECTORY;
		}
		ret = SMB_VFS_UNLINK(conn,directory);
	} else {
		ret = SMB_VFS_RMDIR(conn,directory);
	}
	if (ret == 0) {
		notify_fname(conn, NOTIFY_ACTION_REMOVED,
			     FILE_NOTIFY_CHANGE_DIR_NAME,
			     directory);
		return NT_STATUS_OK;
	}

	if(((errno == ENOTEMPTY)||(errno == EEXIST)) && lp_veto_files(SNUM(conn))) {
		/*
		 * Check to see if the only thing in this directory are
		 * vetoed files/directories. If so then delete them and
		 * retry. If we fail to delete any of them (and we *don't*
		 * do a recursive delete) then fail the rmdir.
		 */
		const char *dname;
		long dirpos = 0;
		struct smb_Dir *dir_hnd = OpenDir(talloc_tos(), conn,
						  directory, NULL, 0);

		if(dir_hnd == NULL) {
			errno = ENOTEMPTY;
			goto err;
		}

		while ((dname = ReadDirName(dir_hnd,&dirpos))) {
			if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
				continue;
			if (!is_visible_file(conn, directory, dname, &st, False))
				continue;
			if(!IS_VETO_PATH(conn, dname)) {
				TALLOC_FREE(dir_hnd);
				errno = ENOTEMPTY;
				goto err;
			}
		}

		/* We only have veto files/directories.
		 * Are we allowed to delete them ? */

		if(!lp_recursive_veto_delete(SNUM(conn))) {
			TALLOC_FREE(dir_hnd);
			errno = ENOTEMPTY;
			goto err;
		}

		/* Do a recursive delete. */
		RewindDir(dir_hnd,&dirpos);
		while ((dname = ReadDirName(dir_hnd,&dirpos))) {
			char *fullname = NULL;

			if (ISDOT(dname) || ISDOTDOT(dname)) {
				continue;
			}
			if (!is_visible_file(conn, directory, dname, &st, False)) {
				continue;
			}

			fullname = talloc_asprintf(ctx,
					"%s/%s",
					directory,
					dname);

			if(!fullname) {
				errno = ENOMEM;
				break;
			}

			if(SMB_VFS_LSTAT(conn,fullname, &st) != 0) {
				break;
			}
			if(st.st_mode & S_IFDIR) {
				if(!recursive_rmdir(ctx, conn, fullname)) {
					break;
				}
				if(SMB_VFS_RMDIR(conn,fullname) != 0) {
					break;
				}
			} else if(SMB_VFS_UNLINK(conn,fullname) != 0) {
				break;
			}
			TALLOC_FREE(fullname);
		}
		TALLOC_FREE(dir_hnd);
		/* Retry the rmdir */
		ret = SMB_VFS_RMDIR(conn,directory);
	}

  err:

	if (ret != 0) {
		DEBUG(3,("rmdir_internals: couldn't remove directory %s : "
			 "%s\n", directory,strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	notify_fname(conn, NOTIFY_ACTION_REMOVED,
		     FILE_NOTIFY_CHANGE_DIR_NAME,
		     directory);

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a rmdir.
****************************************************************************/

void reply_rmdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *directory = NULL;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBrmdir);

	srvstr_get_path(ctx, (char *)req->inbuf, req->flags2, &directory,
			smb_buf(req->inbuf) + 1, 0,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBrmdir);
		return;
	}

	status = resolve_dfspath(ctx, conn,
				 req->flags2 & FLAGS2_DFS_PATHNAMES,
				 directory,
				 &directory);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBrmdir);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBrmdir);
		return;
	}

	status = unix_convert(ctx, conn, directory, False, &directory,
			NULL, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBrmdir);
		return;
	}

	status = check_name(conn, directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBrmdir);
		return;
	}

	dptr_closepath(directory, req->smbpid);
	status = rmdir_internals(ctx, conn, directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBrmdir);
		return;
	}

	reply_outbuf(req, 0, 0);

	DEBUG( 3, ( "rmdir %s\n", directory ) );

	END_PROFILE(SMBrmdir);
	return;
}

/*******************************************************************
 Resolve wildcards in a filename rename.
********************************************************************/

static bool resolve_wildcards(TALLOC_CTX *ctx,
				const char *name1,
				const char *name2,
				char **pp_newname)
{
	char *name2_copy = NULL;
	char *root1 = NULL;
	char *root2 = NULL;
	char *ext1 = NULL;
	char *ext2 = NULL;
	char *p,*p2, *pname1, *pname2;
	
	name2_copy = talloc_strdup(ctx, name2);
	if (!name2_copy) {
		return False;
	}

	pname1 = strrchr_m(name1,'/');
	pname2 = strrchr_m(name2_copy,'/');

	if (!pname1 || !pname2) {
		return False;
	}
  
	/* Truncate the copy of name2 at the last '/' */
	*pname2 = '\0';

	/* Now go past the '/' */
	pname1++;
	pname2++;

	root1 = talloc_strdup(ctx, pname1);
	root2 = talloc_strdup(ctx, pname2);

	if (!root1 || !root2) {
		return False;
	}

	p = strrchr_m(root1,'.');
	if (p) {
		*p = 0;
		ext1 = talloc_strdup(ctx, p+1);
	} else {
		ext1 = talloc_strdup(ctx, "");
	}
	p = strrchr_m(root2,'.');
	if (p) {
		*p = 0;
		ext2 = talloc_strdup(ctx, p+1);
	} else {
		ext2 = talloc_strdup(ctx, "");
	}

	if (!ext1 || !ext2) {
		return False;
	}

	p = root1;
	p2 = root2;
	while (*p2) {
		if (*p2 == '?') {
			/* Hmmm. Should this be mb-aware ? */
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			*p2 = '\0';
			root2 = talloc_asprintf(ctx, "%s%s",
						root2,
						p);
			if (!root2) {
				return False;
			}
			break;
		} else {
			p2++;
		}
		if (*p) {
			p++;
		}
	}

	p = ext1;
	p2 = ext2;
	while (*p2) {
		if (*p2 == '?') {
			/* Hmmm. Should this be mb-aware ? */
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			*p2 = '\0';
			ext2 = talloc_asprintf(ctx, "%s%s",
						ext2,
						p);
			if (!ext2) {
				return False;
			}
			break;
		} else {
			p2++;
		}
		if (*p) {
			p++;
		}
	}

	if (*ext2) {
		*pp_newname = talloc_asprintf(ctx, "%s/%s.%s",
				name2_copy,
				root2,
				ext2);
	} else {
		*pp_newname = talloc_asprintf(ctx, "%s/%s",
				name2_copy,
				root2);
	}

	if (!*pp_newname) {
		return False;
	}

	return True;
}

/****************************************************************************
 Ensure open files have their names updated. Updated to notify other smbd's
 asynchronously.
****************************************************************************/

static void rename_open_files(connection_struct *conn,
			      struct share_mode_lock *lck,
			      const char *newname)
{
	files_struct *fsp;
	bool did_rename = False;

	for(fsp = file_find_di_first(lck->id); fsp;
	    fsp = file_find_di_next(fsp)) {
		/* fsp_name is a relative path under the fsp. To change this for other
		   sharepaths we need to manipulate relative paths. */
		/* TODO - create the absolute path and manipulate the newname
		   relative to the sharepath. */
		if (!strequal(fsp->conn->connectpath, conn->connectpath)) {
			continue;
		}
		DEBUG(10,("rename_open_files: renaming file fnum %d (file_id %s) from %s -> %s\n",
			  fsp->fnum, file_id_string_tos(&fsp->file_id),
			fsp->fsp_name, newname ));
		string_set(&fsp->fsp_name, newname);
		did_rename = True;
	}

	if (!did_rename) {
		DEBUG(10,("rename_open_files: no open files on file_id %s for %s\n",
			  file_id_string_tos(&lck->id), newname ));
	}

	/* Send messages to all smbd's (not ourself) that the name has changed. */
	rename_share_filename(smbd_messaging_context(), lck, conn->connectpath,
			      newname);
}

/****************************************************************************
 We need to check if the source path is a parent directory of the destination
 (ie. a rename of /foo/bar/baz -> /foo/bar/baz/bibble/bobble. If so we must
 refuse the rename with a sharing violation. Under UNIX the above call can
 *succeed* if /foo/bar/baz is a symlink to another area in the share. We
 probably need to check that the client is a Windows one before disallowing
 this as a UNIX client (one with UNIX extensions) can know the source is a
 symlink and make this decision intelligently. Found by an excellent bug
 report from <AndyLiebman@aol.com>.
****************************************************************************/

static bool rename_path_prefix_equal(const char *src, const char *dest)
{
	const char *psrc = src;
	const char *pdst = dest;
	size_t slen;

	if (psrc[0] == '.' && psrc[1] == '/') {
		psrc += 2;
	}
	if (pdst[0] == '.' && pdst[1] == '/') {
		pdst += 2;
	}
	if ((slen = strlen(psrc)) > strlen(pdst)) {
		return False;
	}
	return ((memcmp(psrc, pdst, slen) == 0) && pdst[slen] == '/');
}

/*
 * Do the notify calls from a rename
 */

static void notify_rename(connection_struct *conn, bool is_dir,
			  const char *oldpath, const char *newpath)
{
	char *olddir, *newdir;
	const char *oldname, *newname;
	uint32 mask;

	mask = is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME
		: FILE_NOTIFY_CHANGE_FILE_NAME;

	if (!parent_dirname_talloc(NULL, oldpath, &olddir, &oldname)
	    || !parent_dirname_talloc(NULL, newpath, &newdir, &newname)) {
		TALLOC_FREE(olddir);
		return;
	}

	if (strcmp(olddir, newdir) == 0) {
		notify_fname(conn, NOTIFY_ACTION_OLD_NAME, mask, oldpath);
		notify_fname(conn, NOTIFY_ACTION_NEW_NAME, mask, newpath);
	}
	else {
		notify_fname(conn, NOTIFY_ACTION_REMOVED, mask, oldpath);
		notify_fname(conn, NOTIFY_ACTION_ADDED, mask, newpath);
	}
	TALLOC_FREE(olddir);
	TALLOC_FREE(newdir);

	/* this is a strange one. w2k3 gives an additional event for
	   CHANGE_ATTRIBUTES and CHANGE_CREATION on the new file when renaming
	   files, but not directories */
	if (!is_dir) {
		notify_fname(conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES
			     |FILE_NOTIFY_CHANGE_CREATION,
			     newpath);
	}
}

/****************************************************************************
 Rename an open file - given an fsp.
****************************************************************************/

NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			char *newname,
			const char *newname_last_component,
			uint32 attrs,
			bool replace_if_exists)
{
	TALLOC_CTX *ctx = talloc_tos();
	SMB_STRUCT_STAT sbuf, sbuf1;
	NTSTATUS status = NT_STATUS_OK;
	struct share_mode_lock *lck = NULL;
	bool dst_exists, old_is_stream, new_is_stream;

	ZERO_STRUCT(sbuf);

	status = check_name(conn, newname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure newname contains a '/' */
	if(strrchr_m(newname,'/') == 0) {
		newname = talloc_asprintf(ctx,
					"./%s",
					newname);
		if (!newname) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * Check for special case with case preserving and not
	 * case sensitive. If the old last component differs from the original
	 * last component only by case, then we should allow
	 * the rename (user is trying to change the case of the
	 * filename).
	 */

	if((conn->case_sensitive == False) && (conn->case_preserve == True) &&
			strequal(newname, fsp->fsp_name)) {
		char *p;
		char *newname_modified_last_component = NULL;

		/*
		 * Get the last component of the modified name.
		 * Note that we guarantee that newname contains a '/'
		 * character above.
		 */
		p = strrchr_m(newname,'/');
		newname_modified_last_component = talloc_strdup(ctx,
						p+1);
		if (!newname_modified_last_component) {
			return NT_STATUS_NO_MEMORY;
		}

		if(strcsequal(newname_modified_last_component,
			      newname_last_component) == False) {
			/*
			 * Replace the modified last component with
			 * the original.
			 */
			*p = '\0'; /* Truncate at the '/' */
			newname = talloc_asprintf(ctx,
					"%s/%s",
					newname,
					newname_last_component);
		}
	}

	/*
	 * If the src and dest names are identical - including case,
	 * don't do the rename, just return success.
	 */

	if (strcsequal(fsp->fsp_name, newname)) {
		DEBUG(3,("rename_internals_fsp: identical names in rename %s - returning success\n",
			newname));
		return NT_STATUS_OK;
	}

	old_is_stream = is_ntfs_stream_name(fsp->fsp_name);
	new_is_stream = is_ntfs_stream_name(newname);

	/* Return the correct error code if both names aren't streams. */
	if (!old_is_stream && new_is_stream) {
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	if (old_is_stream && !new_is_stream) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Have vfs_object_exist also fill sbuf1
	 */
	dst_exists = vfs_object_exist(conn, newname, &sbuf1);

	if(!replace_if_exists && dst_exists) {
		DEBUG(3,("rename_internals_fsp: dest exists doing rename %s -> %s\n",
			fsp->fsp_name,newname));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if (dst_exists) {
		struct file_id fileid = vfs_file_id_from_sbuf(conn, &sbuf1);
		files_struct *dst_fsp = file_find_di_first(fileid);
		/* The file can be open when renaming a stream */
		if (dst_fsp && !new_is_stream) {
			DEBUG(3, ("rename_internals_fsp: Target file open\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	/* Ensure we have a valid stat struct for the source. */
	if (fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		int ret = -1;
		if (fsp->posix_open) {
			ret = SMB_VFS_LSTAT(conn,fsp->fsp_name,&sbuf);
		} else {
			ret = SMB_VFS_STAT(conn,fsp->fsp_name,&sbuf);
		}
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	status = can_rename(conn, fsp, attrs, &sbuf);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3,("rename_internals_fsp: Error %s rename %s -> %s\n",
			nt_errstr(status), fsp->fsp_name,newname));
		if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION))
			status = NT_STATUS_ACCESS_DENIED;
		return status;
	}

	if (rename_path_prefix_equal(fsp->fsp_name, newname)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	lck = get_share_mode_lock(talloc_tos(), fsp->file_id, NULL, NULL,
				  NULL);

	/*
	 * We have the file open ourselves, so not being able to get the
	 * corresponding share mode lock is a fatal error.
	 */

	SMB_ASSERT(lck != NULL);

	if(SMB_VFS_RENAME(conn,fsp->fsp_name, newname) == 0) {
		uint32 create_options = fsp->fh->private_options;

		DEBUG(3,("rename_internals_fsp: succeeded doing rename on %s -> %s\n",
			fsp->fsp_name,newname));

		notify_rename(conn, fsp->is_directory, fsp->fsp_name, newname);

		rename_open_files(conn, lck, newname);

		/*
		 * A rename acts as a new file create w.r.t. allowing an initial delete
		 * on close, probably because in Windows there is a new handle to the
		 * new file. If initial delete on close was requested but not
		 * originally set, we need to set it here. This is probably not 100% correct,
		 * but will work for the CIFSFS client which in non-posix mode
		 * depends on these semantics. JRA.
		 */

		if (create_options & FILE_DELETE_ON_CLOSE) {
			status = can_set_delete_on_close(fsp, True, 0);

			if (NT_STATUS_IS_OK(status)) {
				/* Note that here we set the *inital* delete on close flag,
				 * not the regular one. The magic gets handled in close. */
				fsp->initial_delete_on_close = True;
			}
		}
		TALLOC_FREE(lck);
		return NT_STATUS_OK;
	}

	TALLOC_FREE(lck);

	if (errno == ENOTDIR || errno == EISDIR) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
	} else {
		status = map_nt_error_from_unix(errno);
	}

	DEBUG(3,("rename_internals_fsp: Error %s rename %s -> %s\n",
		nt_errstr(status), fsp->fsp_name,newname));

	return status;
}

/****************************************************************************
 The guts of the rename command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			const char *name_in,
			const char *newname_in,
			uint32 attrs,
			bool replace_if_exists,
			bool src_has_wild,
			bool dest_has_wild,
			uint32_t access_mask)
{
	char *directory = NULL;
	char *mask = NULL;
	char *last_component_src = NULL;
	char *last_component_dest = NULL;
	char *name = NULL;
	char *newname = NULL;
	char *p;
	int count=0;
	NTSTATUS status = NT_STATUS_OK;
	SMB_STRUCT_STAT sbuf1, sbuf2;
	struct smb_Dir *dir_hnd = NULL;
	const char *dname;
	long offset = 0;
	bool posix_pathnames = lp_posix_pathnames();

	ZERO_STRUCT(sbuf1);
	ZERO_STRUCT(sbuf2);

	status = unix_convert(ctx, conn, name_in, src_has_wild, &name,
			&last_component_src, &sbuf1);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = unix_convert(ctx, conn, newname_in, dest_has_wild, &newname,
			&last_component_dest, &sbuf2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Split the old name into directory and last component
	 * strings. Note that unix_convert may have stripped off a
	 * leading ./ from both name and newname if the rename is
	 * at the root of the share. We need to make sure either both
	 * name and newname contain a / character or neither of them do
	 * as this is checked in resolve_wildcards().
	 */

	p = strrchr_m(name,'/');
	if (!p) {
		directory = talloc_strdup(ctx, ".");
		if (!directory) {
			return NT_STATUS_NO_MEMORY;
		}
		mask = name;
	} else {
		*p = 0;
		directory = talloc_strdup(ctx, name);
		if (!directory) {
			return NT_STATUS_NO_MEMORY;
		}
		mask = p+1;
		*p = '/'; /* Replace needed for exceptional test below. */
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!VALID_STAT(sbuf1) && mangle_is_mangled(mask, conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx,
					mask,
					&new_mask,
					conn->params );
		if (new_mask) {
			mask = new_mask;
		}
	}

	if (!src_has_wild) {
		files_struct *fsp;

		/*
		 * No wildcards - just process the one file.
		 */
		bool is_short_name = mangle_is_8_3(name, True, conn->params);

		/* Add a terminating '/' to the directory name. */
		directory = talloc_asprintf_append(directory,
				"/%s",
				mask);
		if (!directory) {
			return NT_STATUS_NO_MEMORY;
		}

		/* Ensure newname contains a '/' also */
		if(strrchr_m(newname,'/') == 0) {
			newname = talloc_asprintf(ctx,
						"./%s",
						newname);
			if (!newname) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		DEBUG(3, ("rename_internals: case_sensitive = %d, "
			  "case_preserve = %d, short case preserve = %d, "
			  "directory = %s, newname = %s, "
			  "last_component_dest = %s, is_8_3 = %d\n",
			  conn->case_sensitive, conn->case_preserve,
			  conn->short_case_preserve, directory,
			  newname, last_component_dest, is_short_name));

		/* The dest name still may have wildcards. */
		if (dest_has_wild) {
			char *mod_newname = NULL;
			if (!resolve_wildcards(ctx,
					directory,newname,&mod_newname)) {
				DEBUG(6, ("rename_internals: resolve_wildcards "
					"%s %s failed\n",
					directory,
					newname));
				return NT_STATUS_NO_MEMORY;
			}
			newname = mod_newname;
		}

		ZERO_STRUCT(sbuf1);
		if (posix_pathnames) {
			SMB_VFS_LSTAT(conn, directory, &sbuf1);
		} else {
			SMB_VFS_STAT(conn, directory, &sbuf1);
		}

		status = S_ISDIR(sbuf1.st_mode) ?
			open_directory(conn, req, directory, &sbuf1,
					access_mask,
					FILE_SHARE_READ|FILE_SHARE_WRITE,
					FILE_OPEN,
					0,
					posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0,
					NULL,
					&fsp)
			: open_file_ntcreate(conn, req, directory, &sbuf1,
					access_mask,
					FILE_SHARE_READ|FILE_SHARE_WRITE,
					FILE_OPEN,
					0,
					posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0,
					0,
					NULL,
					&fsp);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not open rename source %s: %s\n",
				  directory, nt_errstr(status)));
			return status;
		}

		status = rename_internals_fsp(conn, fsp, newname,
					      last_component_dest,
					      attrs, replace_if_exists);

		close_file(fsp, NORMAL_CLOSE);

		DEBUG(3, ("rename_internals: Error %s rename %s -> %s\n",
			  nt_errstr(status), directory,newname));

		return status;
	}

	/*
	 * Wildcards - process each file that matches.
	 */
	if (strequal(mask,"????????.???")) {
		mask[0] = '*';
		mask[1] = '\0';
	}

	status = check_name(conn, directory);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dir_hnd = OpenDir(talloc_tos(), conn, directory, mask, attrs);
	if (dir_hnd == NULL) {
		return map_nt_error_from_unix(errno);
	}

	status = NT_STATUS_NO_SUCH_FILE;
	/*
	 * Was status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	 * - gentest fix. JRA
	 */

	while ((dname = ReadDirName(dir_hnd, &offset))) {
		files_struct *fsp = NULL;
		char *fname = NULL;
		char *destname = NULL;
		bool sysdir_entry = False;

		/* Quick check for "." and ".." */
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			if (attrs & aDIR) {
				sysdir_entry = True;
			} else {
				continue;
			}
		}

		if (!is_visible_file(conn, directory, dname, &sbuf1, False)) {
			continue;
		}

		if(!mask_match(dname, mask, conn->case_sensitive)) {
			continue;
		}

		if (sysdir_entry) {
			status = NT_STATUS_OBJECT_NAME_INVALID;
			break;
		}

		fname = talloc_asprintf(ctx,
				"%s/%s",
				directory,
				dname);
		if (!fname) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!resolve_wildcards(ctx,
				fname,newname,&destname)) {
			DEBUG(6, ("resolve_wildcards %s %s failed\n",
				  fname, destname));
			TALLOC_FREE(fname);
			continue;
		}
		if (!destname) {
			return NT_STATUS_NO_MEMORY;
		}

		ZERO_STRUCT(sbuf1);
		if (posix_pathnames) {
			SMB_VFS_LSTAT(conn, fname, &sbuf1);
		} else {
			SMB_VFS_STAT(conn, fname, &sbuf1);
		}

		status = S_ISDIR(sbuf1.st_mode) ?
			open_directory(conn, req, fname, &sbuf1,
					access_mask,
					FILE_SHARE_READ|FILE_SHARE_WRITE,
					FILE_OPEN,
					0,
					posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0,
					NULL,
					&fsp)
			: open_file_ntcreate(conn, req, fname, &sbuf1,
					access_mask,
					FILE_SHARE_READ|FILE_SHARE_WRITE,
					FILE_OPEN,
					0,
					posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0,
					0,
					NULL,
					&fsp);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("rename_internals: open_file_ntcreate "
				 "returned %s rename %s -> %s\n",
				 nt_errstr(status), directory, newname));
			break;
		}

		status = rename_internals_fsp(conn, fsp, destname, dname,
					      attrs, replace_if_exists);

		close_file(fsp, NORMAL_CLOSE);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("rename_internals_fsp returned %s for "
				  "rename %s -> %s\n", nt_errstr(status),
				  directory, newname));
			break;
		}

		count++;

		DEBUG(3,("rename_internals: doing rename on %s -> "
			 "%s\n",fname,destname));

		TALLOC_FREE(fname);
		TALLOC_FREE(destname);
	}
	TALLOC_FREE(dir_hnd);

	if (count == 0 && NT_STATUS_IS_OK(status) && errno != 0) {
		status = map_nt_error_from_unix(errno);
	}

	return status;
}

/****************************************************************************
 Reply to a mv.
****************************************************************************/

void reply_mv(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	char *newname = NULL;
	char *p;
	uint32 attrs;
	NTSTATUS status;
	bool src_has_wcard = False;
	bool dest_has_wcard = False;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBmv);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBmv);
		return;
	}

	attrs = SVAL(req->inbuf,smb_vwv0);

	p = smb_buf(req->inbuf) + 1;
	p += srvstr_get_path_wcard(ctx, (char *)req->inbuf, req->flags2, &name, p,
				   0, STR_TERMINATE, &status,
				   &src_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBmv);
		return;
	}
	p++;
	p += srvstr_get_path_wcard(ctx, (char *)req->inbuf, req->flags2, &newname, p,
				   0, STR_TERMINATE, &status,
				   &dest_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBmv);
		return;
	}

	status = resolve_dfspath_wcard(ctx, conn,
				       req->flags2 & FLAGS2_DFS_PATHNAMES,
				       name,
				       &name,
				       &src_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBmv);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBmv);
		return;
	}

	status = resolve_dfspath_wcard(ctx, conn,
				       req->flags2 & FLAGS2_DFS_PATHNAMES,
				       newname,
				       &newname,
				       &dest_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBmv);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBmv);
		return;
	}

	DEBUG(3,("reply_mv : %s -> %s\n",name,newname));

	status = rename_internals(ctx, conn, req, name, newname, attrs, False,
				  src_has_wcard, dest_has_wcard, DELETE_ACCESS);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->mid)) {
			/* We have re-scheduled this call. */
			END_PROFILE(SMBmv);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBmv);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBmv);
	return;
}

/*******************************************************************
 Copy a file as part of a reply_copy.
******************************************************************/

/*
 * TODO: check error codes on all callers
 */

NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *src,
			const char *dest1,
			int ofun,
			int count,
			bool target_is_directory)
{
	SMB_STRUCT_STAT src_sbuf, sbuf2;
	SMB_OFF_T ret=-1;
	files_struct *fsp1,*fsp2;
	char *dest = NULL;
 	uint32 dosattrs;
	uint32 new_create_disposition;
	NTSTATUS status;

	dest = talloc_strdup(ctx, dest1);
	if (!dest) {
		return NT_STATUS_NO_MEMORY;
	}
	if (target_is_directory) {
		const char *p = strrchr_m(src,'/');
		if (p) {
			p++;
		} else {
			p = src;
		}
		dest = talloc_asprintf_append(dest,
				"/%s",
				p);
		if (!dest) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!vfs_file_exist(conn,src,&src_sbuf)) {
		TALLOC_FREE(dest);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!target_is_directory && count) {
		new_create_disposition = FILE_OPEN;
	} else {
		if (!map_open_params_to_ntcreate(dest1,0,ofun,
				NULL, NULL, &new_create_disposition, NULL)) {
			TALLOC_FREE(dest);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	status = open_file_ntcreate(conn, NULL, src, &src_sbuf,
			FILE_GENERIC_READ,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			FILE_OPEN,
			0,
			FILE_ATTRIBUTE_NORMAL,
			INTERNAL_OPEN_ONLY,
			NULL, &fsp1);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(dest);
		return status;
	}

	dosattrs = dos_mode(conn, src, &src_sbuf);
	if (SMB_VFS_STAT(conn,dest,&sbuf2) == -1) {
		ZERO_STRUCTP(&sbuf2);
	}

	status = open_file_ntcreate(conn, NULL, dest, &sbuf2,
			FILE_GENERIC_WRITE,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			new_create_disposition,
			0,
			dosattrs,
			INTERNAL_OPEN_ONLY,
			NULL, &fsp2);

	TALLOC_FREE(dest);

	if (!NT_STATUS_IS_OK(status)) {
		close_file(fsp1,ERROR_CLOSE);
		return status;
	}

	if ((ofun&3) == 1) {
		if(SMB_VFS_LSEEK(fsp2,0,SEEK_END) == -1) {
			DEBUG(0,("copy_file: error - vfs lseek returned error %s\n", strerror(errno) ));
			/*
			 * Stop the copy from occurring.
			 */
			ret = -1;
			src_sbuf.st_size = 0;
		}
	}

	if (src_sbuf.st_size) {
		ret = vfs_transfer_file(fsp1, fsp2, src_sbuf.st_size);
	}

	close_file(fsp1,NORMAL_CLOSE);

	/* Ensure the modtime is set correctly on the destination file. */
	set_close_write_time(fsp2, get_mtimespec(&src_sbuf));

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	status = close_file(fsp2,NORMAL_CLOSE);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (ret != (SMB_OFF_T)src_sbuf.st_size) {
		return NT_STATUS_DISK_FULL;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a file copy.
****************************************************************************/

void reply_copy(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	char *newname = NULL;
	char *directory = NULL;
	char *mask = NULL;
	char *p;
	int count=0;
	int error = ERRnoaccess;
	int err = 0;
	int tid2;
	int ofun;
	int flags;
	bool target_is_directory=False;
	bool source_has_wild = False;
	bool dest_has_wild = False;
	SMB_STRUCT_STAT sbuf1, sbuf2;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcopy);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBcopy);
		return;
	}

	tid2 = SVAL(req->inbuf,smb_vwv0);
	ofun = SVAL(req->inbuf,smb_vwv1);
	flags = SVAL(req->inbuf,smb_vwv2);

	p = smb_buf(req->inbuf);
	p += srvstr_get_path_wcard(ctx, (char *)req->inbuf, req->flags2, &name, p,
				   0, STR_TERMINATE, &status,
				   &source_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}
	p += srvstr_get_path_wcard(ctx, (char *)req->inbuf, req->flags2, &newname, p,
				   0, STR_TERMINATE, &status,
				   &dest_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}

	DEBUG(3,("reply_copy : %s -> %s\n",name,newname));

	if (tid2 != conn->cnum) {
		/* can't currently handle inter share copies XXXX */
		DEBUG(3,("Rejecting inter-share copy\n"));
		reply_doserror(req, ERRSRV, ERRinvdevice);
		END_PROFILE(SMBcopy);
		return;
	}

	status = resolve_dfspath_wcard(ctx, conn,
				       req->flags2 & FLAGS2_DFS_PATHNAMES,
				       name,
				       &name,
				       &source_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBcopy);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}

	status = resolve_dfspath_wcard(ctx, conn,
				       req->flags2 & FLAGS2_DFS_PATHNAMES,
				       newname,
				       &newname,
				       &dest_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBcopy);
			return;
		}
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}

	status = unix_convert(ctx, conn, name, source_has_wild,
			&name, NULL, &sbuf1);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}

	status = unix_convert(ctx, conn, newname, dest_has_wild,
			&newname, NULL, &sbuf2);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBcopy);
		return;
	}

	target_is_directory = VALID_STAT_OF_DIR(sbuf2);

	if ((flags&1) && target_is_directory) {
		reply_doserror(req, ERRDOS, ERRbadfile);
		END_PROFILE(SMBcopy);
		return;
	}

	if ((flags&2) && !target_is_directory) {
		reply_doserror(req, ERRDOS, ERRbadpath);
		END_PROFILE(SMBcopy);
		return;
	}

	if ((flags&(1<<5)) && VALID_STAT_OF_DIR(sbuf1)) {
		/* wants a tree copy! XXXX */
		DEBUG(3,("Rejecting tree copy\n"));
		reply_doserror(req, ERRSRV, ERRerror);
		END_PROFILE(SMBcopy);
		return;
	}

	p = strrchr_m(name,'/');
	if (!p) {
		directory = talloc_strdup(ctx, "./");
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBcopy);
			return;
		}
		mask = name;
	} else {
		*p = 0;
		directory = talloc_strdup(ctx, name);
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBcopy);
			return;
		}
		mask = p+1;
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!VALID_STAT(sbuf1) && mangle_is_mangled(mask, conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx,
					mask,
					&new_mask,
					conn->params );
		if (new_mask) {
			mask = new_mask;
		}
	}

	if (!source_has_wild) {
		directory = talloc_asprintf_append(directory,
				"/%s",
				mask);
		if (dest_has_wild) {
			char *mod_newname = NULL;
			if (!resolve_wildcards(ctx,
					directory,newname,&mod_newname)) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBcopy);
				return;
			}
			newname = mod_newname;
		}

		status = check_name(conn, directory);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBcopy);
			return;
		}

		status = check_name(conn, newname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBcopy);
			return;
		}

		status = copy_file(ctx,conn,directory,newname,ofun,
				count,target_is_directory);

		if(!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBcopy);
			return;
		} else {
			count++;
		}
	} else {
		struct smb_Dir *dir_hnd = NULL;
		const char *dname = NULL;
		long offset = 0;

		if (strequal(mask,"????????.???")) {
			mask[0] = '*';
			mask[1] = '\0';
		}

		status = check_name(conn, directory);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			END_PROFILE(SMBcopy);
			return;
		}

		dir_hnd = OpenDir(talloc_tos(), conn, directory, mask, 0);
		if (dir_hnd == NULL) {
			status = map_nt_error_from_unix(errno);
			reply_nterror(req, status);
			END_PROFILE(SMBcopy);
			return;
		}

		error = ERRbadfile;

		while ((dname = ReadDirName(dir_hnd, &offset))) {
			char *destname = NULL;
			char *fname = NULL;

			if (ISDOT(dname) || ISDOTDOT(dname)) {
				continue;
			}

			if (!is_visible_file(conn, directory, dname, &sbuf1, False)) {
				continue;
			}

			if(!mask_match(dname, mask, conn->case_sensitive)) {
				continue;
			}

			error = ERRnoaccess;
			fname = talloc_asprintf(ctx,
					"%s/%s",
					directory,
					dname);
			if (!fname) {
				TALLOC_FREE(dir_hnd);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBcopy);
				return;
			}

			if (!resolve_wildcards(ctx,
					fname,newname,&destname)) {
				continue;
			}
			if (!destname) {
				TALLOC_FREE(dir_hnd);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				END_PROFILE(SMBcopy);
				return;
			}

			status = check_name(conn, fname);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				reply_nterror(req, status);
				END_PROFILE(SMBcopy);
				return;
			}

			status = check_name(conn, destname);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				reply_nterror(req, status);
				END_PROFILE(SMBcopy);
				return;
			}

			DEBUG(3,("reply_copy : doing copy on %s -> %s\n",fname, destname));

			status = copy_file(ctx,conn,fname,destname,ofun,
					count,target_is_directory);
			if (NT_STATUS_IS_OK(status)) {
				count++;
			}
			TALLOC_FREE(fname);
			TALLOC_FREE(destname);
		}
		TALLOC_FREE(dir_hnd);
	}

	if (count == 0) {
		if(err) {
			/* Error on close... */
			errno = err;
			reply_unixerror(req, ERRHRD, ERRgeneral);
			END_PROFILE(SMBcopy);
			return;
		}

		reply_doserror(req, ERRDOS, error);
		END_PROFILE(SMBcopy);
		return;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,count);

	END_PROFILE(SMBcopy);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Get a lock pid, dealing with large count requests.
****************************************************************************/

uint32 get_lock_pid( char *data, int data_offset, bool large_file_format)
{
	if(!large_file_format)
		return (uint32)SVAL(data,SMB_LPID_OFFSET(data_offset));
	else
		return (uint32)SVAL(data,SMB_LARGE_LPID_OFFSET(data_offset));
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/

SMB_BIG_UINT get_lock_count( char *data, int data_offset, bool large_file_format)
{
	SMB_BIG_UINT count = 0;

	if(!large_file_format) {
		count = (SMB_BIG_UINT)IVAL(data,SMB_LKLEN_OFFSET(data_offset));
	} else {

#if defined(HAVE_LONGLONG)
		count = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) << 32) |
			((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints truncate the
		 * lock count by dropping the top 32 bits.
		 */

		if(IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)) != 0) {
			DEBUG(3,("get_lock_count: truncating lock count (high)0x%x (low)0x%x to just low count.\n",
				(unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)),
				(unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)) ));
				SIVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset),0);
		}

		count = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
	}

	return count;
}

#if !defined(HAVE_LONGLONG)
/****************************************************************************
 Pathetically try and map a 64 bit lock offset into 31 bits. I hate Windows :-).
****************************************************************************/

static uint32 map_lock_offset(uint32 high, uint32 low)
{
	unsigned int i;
	uint32 mask = 0;
	uint32 highcopy = high;
 
	/*
	 * Try and find out how many significant bits there are in high.
	 */
 
	for(i = 0; highcopy; i++)
		highcopy >>= 1;
 
	/*
	 * We use 31 bits not 32 here as POSIX
	 * lock offsets may not be negative.
	 */
 
	mask = (~0) << (31 - i);
 
	if(low & mask)
		return 0; /* Fail. */
 
	high <<= (31 - i);
 
	return (high|low);
}
#endif /* !defined(HAVE_LONGLONG) */

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

SMB_BIG_UINT get_lock_offset( char *data, int data_offset, bool large_file_format, bool *err)
{
	SMB_BIG_UINT offset = 0;

	*err = False;

	if(!large_file_format) {
		offset = (SMB_BIG_UINT)IVAL(data,SMB_LKOFF_OFFSET(data_offset));
	} else {

#if defined(HAVE_LONGLONG)
		offset = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) << 32) |
				((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints mangle the
		 * lock offset by mapping the top 32 bits onto the lower 32.
		 */
      
		if(IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset)) != 0) {
			uint32 low = IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
			uint32 high = IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset));
			uint32 new_low = 0;

			if((new_low = map_lock_offset(high, low)) == 0) {
				*err = True;
				return (SMB_BIG_UINT)-1;
			}

			DEBUG(3,("get_lock_offset: truncating lock offset (high)0x%x (low)0x%x to offset 0x%x.\n",
				(unsigned int)high, (unsigned int)low, (unsigned int)new_low ));
			SIVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset),0);
			SIVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset),new_low);
		}

		offset = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
	}

	return offset;
}

/****************************************************************************
 Reply to a lockingX request.
****************************************************************************/

void reply_lockingX(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	unsigned char locktype;
	unsigned char oplocklevel;
	uint16 num_ulocks;
	uint16 num_locks;
	SMB_BIG_UINT count = 0, offset = 0;
	uint32 lock_pid;
	int32 lock_timeout;
	int i;
	char *data;
	bool large_file_format;
	bool err;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	START_PROFILE(SMBlockingX);

	if (req->wct < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}
	
	fsp = file_fsp(SVAL(req->inbuf,smb_vwv2));
	locktype = CVAL(req->inbuf,smb_vwv3);
	oplocklevel = CVAL(req->inbuf,smb_vwv3+1);
	num_ulocks = SVAL(req->inbuf,smb_vwv6);
	num_locks = SVAL(req->inbuf,smb_vwv7);
	lock_timeout = IVAL(req->inbuf,smb_vwv4);
	large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES)?True:False;

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockingX);
		return;
	}
	
	data = smb_buf(req->inbuf);

	if (locktype & LOCKING_ANDX_CHANGE_LOCKTYPE) {
		/* we don't support these - and CANCEL_LOCK makes w2k
		   and XP reboot so I don't really want to be
		   compatible! (tridge) */
		reply_nterror(req, NT_STATUS_DOS(ERRDOS, ERRnoatomiclocks));
		END_PROFILE(SMBlockingX);
		return;
	}
	
	/* Check if this is an oplock break on a file
	   we have granted an oplock on.
	*/
	if ((locktype & LOCKING_ANDX_OPLOCK_RELEASE)) {
		/* Client can insist on breaking to none. */
		bool break_to_none = (oplocklevel == 0);
		bool result;

		DEBUG(5,("reply_lockingX: oplock break reply (%u) from client "
			 "for fnum = %d\n", (unsigned int)oplocklevel,
			 fsp->fnum ));

		/*
		 * Make sure we have granted an exclusive or batch oplock on
		 * this file.
		 */
		
		if (fsp->oplock_type == 0) {

			/* The Samba4 nbench simulator doesn't understand
			   the difference between break to level2 and break
			   to none from level2 - it sends oplock break
			   replies in both cases. Don't keep logging an error
			   message here - just ignore it. JRA. */

			DEBUG(5,("reply_lockingX: Error : oplock break from "
				 "client for fnum = %d (oplock=%d) and no "
				 "oplock granted on this file (%s).\n",
				 fsp->fnum, fsp->oplock_type, fsp->fsp_name));

			/* if this is a pure oplock break request then don't
			 * send a reply */
			if (num_locks == 0 && num_ulocks == 0) {
				END_PROFILE(SMBlockingX);
				return;
			} else {
				END_PROFILE(SMBlockingX);
				reply_doserror(req, ERRDOS, ERRlock);
				return;
			}
		}

		if ((fsp->sent_oplock_break == BREAK_TO_NONE_SENT) ||
		    (break_to_none)) {
			result = remove_oplock(fsp);
		} else {
			result = downgrade_oplock(fsp);
		}
		
		if (!result) {
			DEBUG(0, ("reply_lockingX: error in removing "
				  "oplock on file %s\n", fsp->fsp_name));
			/* Hmmm. Is this panic justified? */
			smb_panic("internal tdb error");
		}

		reply_to_oplock_break_requests(fsp);

		/* if this is a pure oplock break request then don't send a
		 * reply */
		if (num_locks == 0 && num_ulocks == 0) {
			/* Sanity check - ensure a pure oplock break is not a
			   chained request. */
			if(CVAL(req->inbuf,smb_vwv0) != 0xff)
				DEBUG(0,("reply_lockingX: Error : pure oplock "
					 "break is a chained %d request !\n",
					 (unsigned int)CVAL(req->inbuf,
							    smb_vwv0) ));
			END_PROFILE(SMBlockingX);
			return;
		}
	}

	/*
	 * We do this check *after* we have checked this is not a oplock break
	 * response message. JRA.
	 */
	
	release_level_2_oplocks_on_change(fsp);

	if (smb_buflen(req->inbuf) <
	    (num_ulocks + num_locks) * (large_file_format ? 20 : 10)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}
	
	/* Data now points at the beginning of the list
	   of smb_unlkrng structs */
	for(i = 0; i < (int)num_ulocks; i++) {
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);
		
		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			reply_doserror(req, ERRDOS, ERRnoaccess);
			return;
		}

		DEBUG(10,("reply_lockingX: unlock start=%.0f, len=%.0f for "
			  "pid %u, file %s\n", (double)offset, (double)count,
			  (unsigned int)lock_pid, fsp->fsp_name ));
		
		status = do_unlock(smbd_messaging_context(),
				fsp,
				lock_pid,
				count,
				offset,
				WINDOWS_LOCK);

		if (NT_STATUS_V(status)) {
			END_PROFILE(SMBlockingX);
			reply_nterror(req, status);
			return;
		}
	}

	/* Setup the timeout in seconds. */

	if (!lp_blocking_locks(SNUM(conn))) {
		lock_timeout = 0;
	}
	
	/* Now do any requested locks */
	data += ((large_file_format ? 20 : 10)*num_ulocks);
	
	/* Data now points at the beginning of the list
	   of smb_lkrng structs */
	
	for(i = 0; i < (int)num_locks; i++) {
		enum brl_type lock_type = ((locktype & LOCKING_ANDX_SHARED_LOCK) ?
				READ_LOCK:WRITE_LOCK);
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);
		
		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			reply_doserror(req, ERRDOS, ERRnoaccess);
			return;
		}
		
		DEBUG(10,("reply_lockingX: lock start=%.0f, len=%.0f for pid "
			  "%u, file %s timeout = %d\n", (double)offset,
			  (double)count, (unsigned int)lock_pid,
			  fsp->fsp_name, (int)lock_timeout ));
		
		if (locktype & LOCKING_ANDX_CANCEL_LOCK) {
			if (lp_blocking_locks(SNUM(conn))) {

				/* Schedule a message to ourselves to
				   remove the blocking lock record and
				   return the right error. */

				if (!blocking_lock_cancel(fsp,
						lock_pid,
						offset,
						count,
						WINDOWS_LOCK,
						locktype,
						NT_STATUS_FILE_LOCK_CONFLICT)) {
					END_PROFILE(SMBlockingX);
					reply_nterror(
						req,
						NT_STATUS_DOS(
							ERRDOS,
							ERRcancelviolation));
					return;
				}
			}
			/* Remove a matching pending lock. */
			status = do_lock_cancel(fsp,
						lock_pid,
						count,
						offset,
						WINDOWS_LOCK);
		} else {
			bool blocking_lock = lock_timeout ? True : False;
			bool defer_lock = False;
			struct byte_range_lock *br_lck;
			uint32 block_smbpid;

			br_lck = do_lock(smbd_messaging_context(),
					fsp,
					lock_pid,
					count,
					offset, 
					lock_type,
					WINDOWS_LOCK,
					blocking_lock,
					&status,
					&block_smbpid);

			if (br_lck && blocking_lock && ERROR_WAS_LOCK_DENIED(status)) {
				/* Windows internal resolution for blocking locks seems
				   to be about 200ms... Don't wait for less than that. JRA. */
				if (lock_timeout != -1 && lock_timeout < lp_lock_spin_time()) {
					lock_timeout = lp_lock_spin_time();
				}
				defer_lock = True;
			}

			/* This heuristic seems to match W2K3 very well. If a
			   lock sent with timeout of zero would fail with NT_STATUS_FILE_LOCK_CONFLICT
			   it pretends we asked for a timeout of between 150 - 300 milliseconds as
			   far as I can tell. Replacement for do_lock_spin(). JRA. */

			if (br_lck && lp_blocking_locks(SNUM(conn)) && !blocking_lock &&
					NT_STATUS_EQUAL((status), NT_STATUS_FILE_LOCK_CONFLICT)) {
				defer_lock = True;
				lock_timeout = lp_lock_spin_time();
			}

			if (br_lck && defer_lock) {
				/*
				 * A blocking lock was requested. Package up
				 * this smb into a queued request and push it
				 * onto the blocking lock queue.
				 */
				if(push_blocking_lock_request(br_lck,
							req,
							fsp,
							lock_timeout,
							i,
							lock_pid,
							lock_type,
							WINDOWS_LOCK,
							offset,
							count,
							block_smbpid)) {
					TALLOC_FREE(br_lck);
					END_PROFILE(SMBlockingX);
					return;
				}
			}

			TALLOC_FREE(br_lck);
		}

		if (NT_STATUS_V(status)) {
			END_PROFILE(SMBlockingX);
			reply_nterror(req, status);
			return;
		}
	}
	
	/* If any of the above locks failed, then we must unlock
	   all of the previous locks (X/Open spec). */

	if (!(locktype & LOCKING_ANDX_CANCEL_LOCK) &&
			(i != num_locks) &&
			(num_locks != 0)) {
		/*
		 * Ensure we don't do a remove on the lock that just failed,
		 * as under POSIX rules, if we have a lock already there, we
		 * will delete it (and we shouldn't) .....
		 */
		for(i--; i >= 0; i--) {
			lock_pid = get_lock_pid( data, i, large_file_format);
			count = get_lock_count( data, i, large_file_format);
			offset = get_lock_offset( data, i, large_file_format,
						  &err);
			
			/*
			 * There is no error code marked "stupid client
			 * bug".... :-).
			 */
			if(err) {
				END_PROFILE(SMBlockingX);
				reply_doserror(req, ERRDOS, ERRnoaccess);
				return;
			}
			
			do_unlock(smbd_messaging_context(),
				fsp,
				lock_pid,
				count,
				offset,
				WINDOWS_LOCK);
		}
		END_PROFILE(SMBlockingX);
		reply_nterror(req, status);
		return;
	}

	reply_outbuf(req, 2, 0);
	
	DEBUG(3, ("lockingX fnum=%d type=%d num_locks=%d num_ulocks=%d\n",
		  fsp->fnum, (unsigned int)locktype, num_locks, num_ulocks));
	
	END_PROFILE(SMBlockingX);
	chain_reply(req);
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a SMBreadbmpx (read block multiplex) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbmpx(struct smb_request *req)
{
	START_PROFILE(SMBreadBmpx);
	reply_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBreadbs (read block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbs(struct smb_request *req)
{
	START_PROFILE(SMBreadBs);
	reply_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBs);
	return;
}

/****************************************************************************
 Reply to a SMBsetattrE.
****************************************************************************/

void reply_setattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct timespec ts[2];
	files_struct *fsp;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;

	START_PROFILE(SMBsetattrE);

	if (req->wct < 7) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsetattrE);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if(!fsp || (fsp->conn != conn)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		END_PROFILE(SMBsetattrE);
		return;
	}


	/*
	 * Convert the DOS times into unix times. Ignore create
	 * time as UNIX can't set this.
	 */

	ts[0] = convert_time_t_to_timespec(
		srv_make_unix_date2(req->inbuf+smb_vwv3)); /* atime. */
	ts[1] = convert_time_t_to_timespec(
		srv_make_unix_date2(req->inbuf+smb_vwv5)); /* mtime. */
  
	reply_outbuf(req, 0, 0);

	/* 
	 * Patch from Ray Frush <frush@engr.colostate.edu>
	 * Sometimes times are sent as zero - ignore them.
	 */

	/* Ensure we have a valid stat struct for the source. */
	if (fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			status = map_nt_error_from_unix(errno);
			reply_nterror(req, status);
			END_PROFILE(SMBsetattrE);
			return;
		}
	} else {
		int ret = -1;

		if (fsp->posix_open) {
			ret = SMB_VFS_LSTAT(conn, fsp->fsp_name, &sbuf);
		} else {
			ret = SMB_VFS_STAT(conn, fsp->fsp_name, &sbuf);
		}
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			reply_nterror(req, status);
			END_PROFILE(SMBsetattrE);
			return;
		}
	}

	status = smb_set_file_time(conn, fsp, fsp->fsp_name,
				   &sbuf, ts, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBsetattrE);
		return;
	}
  
	DEBUG( 3, ( "reply_setattrE fnum=%d actime=%u modtime=%u\n",
		fsp->fnum,
		(unsigned int)ts[0].tv_sec,
		(unsigned int)ts[1].tv_sec));

	END_PROFILE(SMBsetattrE);
	return;
}


/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBwritebmpx (write block multiplex primary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebmpx(struct smb_request *req)
{
	START_PROFILE(SMBwriteBmpx);
	reply_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBwritebs (write block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebs(struct smb_request *req)
{
	START_PROFILE(SMBwriteBs);
	reply_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBs);
	return;
}

/****************************************************************************
 Reply to a SMBgetattrE.
****************************************************************************/

void reply_getattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	SMB_STRUCT_STAT sbuf;
	int mode;
	files_struct *fsp;
	struct timespec create_ts;

	START_PROFILE(SMBgetattrE);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBgetattrE);
		return;
	}

	fsp = file_fsp(SVAL(req->inbuf,smb_vwv0));

	if(!fsp || (fsp->conn != conn)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		END_PROFILE(SMBgetattrE);
		return;
	}

	/* Do an fstat on this file */
	if(fsp_stat(fsp, &sbuf)) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		END_PROFILE(SMBgetattrE);
		return;
	}
  
	mode = dos_mode(conn,fsp->fsp_name,&sbuf);
  
	/*
	 * Convert the times into dos times. Set create
	 * date to be last modify date as UNIX doesn't save
	 * this.
	 */

	reply_outbuf(req, 11, 0);

	create_ts = get_create_timespec(&sbuf,
				  lp_fake_dir_create_times(SNUM(conn)));
	srv_put_dos_date2((char *)req->outbuf, smb_vwv0, create_ts.tv_sec);
	srv_put_dos_date2((char *)req->outbuf, smb_vwv2, sbuf.st_atime);
	/* Should we check pending modtime here ? JRA */
	srv_put_dos_date2((char *)req->outbuf, smb_vwv4, sbuf.st_mtime);

	if (mode & aDIR) {
		SIVAL(req->outbuf, smb_vwv6, 0);
		SIVAL(req->outbuf, smb_vwv8, 0);
	} else {
		uint32 allocation_size = get_allocation_size(conn,fsp, &sbuf);
		SIVAL(req->outbuf, smb_vwv6, (uint32)sbuf.st_size);
		SIVAL(req->outbuf, smb_vwv8, allocation_size);
	}
	SSVAL(req->outbuf,smb_vwv10, mode);
  
	DEBUG( 3, ( "reply_getattrE fnum=%d\n", fsp->fnum));
  
	END_PROFILE(SMBgetattrE);
	return;
}
