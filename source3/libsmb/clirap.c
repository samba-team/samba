/*
   Unix SMB/CIFS implementation.
   client RAP calls
   Copyright (C) Andrew Tridgell         1994-1998
   Copyright (C) Gerald (Jerry) Carter   2004
   Copyright (C) James Peach		 2007

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

#include "includes.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/rap.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "libsmb/clirap.h"
#include "trans2.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libcli/smb/reparse.h"
#include "cli_smb2_fnum.h"
#include "lib/util/string_wrappers.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/****************************************************************************
 Call a NetShareEnum - try and browse available connections on a host.
****************************************************************************/

NTSTATUS cli_RNetShareEnum(
	struct cli_state *cli,
	void (*fn)(const char *, uint32_t, const char *, void *),
	void *state)
{
	uint8_t *rparam = NULL;
	uint8_t *rdata = NULL;
	char *rdata_end = NULL;
	char *p = NULL;
	unsigned int rdrcnt,rprcnt;
	char param[1024];
	int count = -1;
	int i, converter;
	int res;
	NTSTATUS status;

	/* now send a SMBtrans command with api RNetShareEnum */
	p = param;
	SSVAL(p,0,0); /* api number */
	p += 2;
	strlcpy(p,"WrLeh",sizeof(param)-PTR_DIFF(p,param));
	p = skip_string(param,sizeof(param),p);
	strlcpy(p,"B13BWz",sizeof(param)-PTR_DIFF(p,param));
	p = skip_string(param,sizeof(param),p);
	SSVAL(p,0,1);
	/*
	 * Win2k needs a *smaller* buffer than 0xFFFF here -
	 * it returns "out of server memory" with 0xFFFF !!! JRA.
	 */
	SSVAL(p,2,0xFFE0);
	p += 4;

	status = cli_trans(talloc_tos(),       /* mem_ctx */
			   cli,		       /* cli */
			   SMBtrans,	       /* cmd */
			   "\\PIPE\\LANMAN",	       /* name */
			   0,		       /* fid */
			   0,		       /* function */
			   0,		       /* flags */
			   NULL,	       /* setup */
			   0,		       /* num_setup */
			   0,		       /* max_setup */
			   (uint8_t *)param,   /* param */
			   PTR_DIFF(p, param), /* num_param */
			   1024,	       /* max_param */
			   NULL,	       /* data */
			   0,		       /* num_data */
			   0xFFE0,	       /* max_data, for W2K */
			   NULL,	       /* recv_flags2 */
			   NULL,	       /* rsetup */
			   0,		       /* min_rsetup */
			   NULL,	       /* num_rsetup */
			   &rparam,	       /* rparam */
			   6,		       /* min_rparam */
			   &rprcnt,	       /* num_rparam */
			   &rdata,	       /* rdata */
			   0,		       /* min_rdata */
			   &rdrcnt);	       /* num_rdata */
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(4,("NetShareEnum failed\n"));
		goto done;
	}

	res = PULL_LE_U16(rparam, 0);

	if (!(res == 0 || res == ERRmoredata)) {
		DEBUG(4,("NetShareEnum res=%d\n", res));
		status = werror_to_ntstatus(W_ERROR(res));
		goto done;
	}

	converter = SVAL(rparam,2);
	rdata_end = (char *)rdata + rdrcnt;

	count=SVAL(rparam,4);
	p = (char *)rdata;

	for (i=0;i<count;i++,p+=20) {
		char *sname;
		int type;
		int comment_offset;
		const char *cmnt;
		const char *p1;
		char *s1, *s2;
		size_t len;
		TALLOC_CTX *frame = talloc_stackframe();

		if (p + 20 > rdata_end) {
			TALLOC_FREE(frame);
			break;
		}

		sname = p;
		type = SVAL(p,14);
		comment_offset = (IVAL(p,16) & 0xFFFF) - converter;
		if (comment_offset < 0 ||
		    comment_offset > (int)rdrcnt) {
			TALLOC_FREE(frame);
			break;
		}
		cmnt = comment_offset ? ((char *)rdata + comment_offset) : "";

		/* Work out the comment length. */
		for (p1 = cmnt, len = 0; *p1 &&
			     p1 < rdata_end; len++)
			p1++;
		if (!*p1) {
			len++;
		}
		pull_string_talloc(frame,rdata,0,
				   &s1,sname,14,STR_ASCII);
		pull_string_talloc(frame,rdata,0,
				   &s2,cmnt,len,STR_ASCII);
		if (!s1 || !s2) {
			TALLOC_FREE(frame);
			continue;
		}

		fn(s1, type, s2, state);

		TALLOC_FREE(frame);
	}

done:
	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);

	return status;
}

/****************************************************************************
 Call a NetServerEnum for the specified workgroup and servertype mask.  This
 function then calls the specified callback function for each name returned.

 The callback function takes 4 arguments: the machine name, the server type,
 the comment and a state pointer.
****************************************************************************/

NTSTATUS cli_NetServerEnum(
	struct cli_state *cli,
	char *workgroup,
	uint32_t stype,
	void (*fn)(const char *, uint32_t, const char *, void *),
	void *state)
{
	uint8_t *rparam = NULL;
	uint8_t *rdata = NULL;
	char *rdata_end = NULL;
	uint32_t rdrcnt, rprcnt;
	char *p;
	char param[1024];
	int uLevel = 1;
	size_t len;
	uint32_t func = RAP_NetServerEnum2;
	char *last_entry = NULL;
	int total_cnt = 0;
	int return_cnt = 0;
	int res;
	NTSTATUS status;

	/*
	 * This may take more than one transaction, so we should loop until
	 * we no longer get a more data to process or we have all of the
	 * items.
	 */
	do {
		/* send a SMBtrans command with api NetServerEnum */
	        p = param;
		SIVAL(p,0,func); /* api number */
	        p += 2;

		if (func == RAP_NetServerEnum3) {
			strlcpy(p,"WrLehDzz", sizeof(param)-PTR_DIFF(p,param));
		} else {
			strlcpy(p,"WrLehDz", sizeof(param)-PTR_DIFF(p,param));
		}

		p = skip_string(param, sizeof(param), p);
		strlcpy(p,"B16BBDz", sizeof(param)-PTR_DIFF(p,param));

		p = skip_string(param, sizeof(param), p);
		SSVAL(p,0,uLevel);
		SSVAL(p,2,CLI_BUFFER_SIZE);
		p += 4;
		SIVAL(p,0,stype);
		p += 4;

		/* If we have more data, tell the server where
		 * to continue from.
		 */
		len = push_ascii(p,
				workgroup,
				sizeof(param) - PTR_DIFF(p,param) - 1,
				STR_TERMINATE|STR_UPPER);

		if (len == 0) {
			SAFE_FREE(last_entry);
			return NT_STATUS_INTERNAL_ERROR;
		}
		p += len;

		if (func == RAP_NetServerEnum3) {
			len = push_ascii(p,
					last_entry ? last_entry : "",
					sizeof(param) - PTR_DIFF(p,param) - 1,
					STR_TERMINATE);

			if (len == 0) {
				SAFE_FREE(last_entry);
				return NT_STATUS_INTERNAL_ERROR;
			}
			p += len;
		}

		/* Next time through we need to use the continue api */
		func = RAP_NetServerEnum3;

		status = cli_trans(talloc_tos(),       /* mem_ctx */
				   cli,		       /* cli */
				   SMBtrans,	       /* cmd */
				   "\\PIPE\\LANMAN",	       /* name */
				   0,		       /* fid */
				   0,		       /* function */
				   0,		       /* flags */
				   NULL,	       /* setup */
				   0,		       /* num_setup */
				   0,		       /* max_setup */
				   (uint8_t *)param,   /* param */
				   PTR_DIFF(p, param), /* num_param */
				   8,		       /* max_param */
				   NULL,	       /* data */
				   0,		       /* num_data */
				   CLI_BUFFER_SIZE,    /* max_data */
				   NULL,	       /* recv_flags2 */
				   NULL,	       /* rsetup */
				   0,		       /* min_rsetup */
				   NULL,	       /* num_rsetup */
				   &rparam,	       /* rparam */
				   6,		       /* min_rparam */
				   &rprcnt,	       /* num_rparam */
				   &rdata,	       /* rdata */
				   0,		       /* min_rdata */
				   &rdrcnt);	       /* num_rdata */
		if (!NT_STATUS_IS_OK(status)) {
			/* break out of the loop on error */
		        res = -1;
		        break;
		}

		rdata_end = (char *)rdata + rdrcnt;

		res = PULL_LE_U16(rparam, 0);

		if (res == 0 || res == ERRmoredata) {
			char *sname = NULL;
			int i, count;
			int converter=SVAL(rparam,2);

			/* Get the number of items returned in this buffer */
			count = SVAL(rparam, 4);

			/* The next field contains the number of items left,
			 * including those returned in this buffer. So the
			 * first time through this should contain all of the
			 * entries.
			 */
			if (total_cnt == 0) {
			        total_cnt = SVAL(rparam, 6);
			}

			/* Keep track of how many we have read */
			return_cnt += count;
			p = (char *)rdata;

			/* The last name in the previous NetServerEnum reply is
			 * sent back to server in the NetServerEnum3 request
			 * (last_entry). The next reply should repeat this entry
			 * as the first element. We have no proof that this is
			 * always true, but from traces that seems to be the
			 * behavior from Window Servers. So first lets do a lot
			 * of checking, just being paranoid. If the string
			 * matches then we already saw this entry so skip it.
			 *
			 * NOTE: sv1_name field must be null terminated and has
			 * a max size of 16 (NetBIOS Name).
			 */
			if (last_entry && count && p &&
				(strncmp(last_entry, p, 16) == 0)) {
			    count -= 1; /* Skip this entry */
			    return_cnt = -1; /* Not part of total, so don't count. */
			    p = (char *)rdata + 26; /* Skip the whole record */
			}

			for (i = 0; i < count; i++, p += 26) {
				int comment_offset;
				const char *cmnt;
				const char *p1;
				char *s1, *s2;
				TALLOC_CTX *frame = talloc_stackframe();
				uint32_t entry_stype;

				if (p + 26 > rdata_end) {
					TALLOC_FREE(frame);
					break;
				}

				sname = p;
				comment_offset = (IVAL(p,22) & 0xFFFF)-converter;
				cmnt = comment_offset ? ((char *)rdata +
							 comment_offset)
						      : "";

				if (comment_offset < 0 || comment_offset >= (int)rdrcnt) {
					TALLOC_FREE(frame);
					continue;
				}

				/* Work out the comment length. */
				for (p1 = cmnt, len = 0; *p1 &&
						p1 < rdata_end; len++)
					p1++;
				if (!*p1) {
					len++;
				}

				entry_stype = IVAL(p,18) & ~SV_TYPE_LOCAL_LIST_ONLY;

				pull_string_talloc(frame,rdata,0,
					&s1,sname,16,STR_ASCII);
				pull_string_talloc(frame,rdata,0,
					&s2,cmnt,len,STR_ASCII);

				if (!s1 || !s2) {
					TALLOC_FREE(frame);
					continue;
				}

				fn(s1, entry_stype, s2, state);
				TALLOC_FREE(frame);
			}

			/* We are done with the old last entry, so now we can free it */
			if (last_entry) {
			        SAFE_FREE(last_entry); /* This will set it to null */
			}

			/* We always make a copy of  the last entry if we have one */
			if (sname) {
			        last_entry = smb_xstrdup(sname);
			}

			/* If we have more data, but no last entry then error out */
			if (!last_entry && (res == ERRmoredata)) {
			        res = 0;
			}

		}

		TALLOC_FREE(rparam);
		TALLOC_FREE(rdata);
	} while ((res == ERRmoredata) && (total_cnt > return_cnt));

	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);
	SAFE_FREE(last_entry);

	if (return_cnt == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Send a SamOEMChangePassword command.
****************************************************************************/

NTSTATUS cli_oem_change_password(struct cli_state *cli,
				 const char *user,
				 const char *new_password,
				 const char *old_password)
{
	char param[1024];
	uint8_t data[532];
	char *p = param;
	unsigned char old_pw_hash[16];
	unsigned char new_pw_hash[16];
	unsigned int param_len = 0;
	uint8_t *rparam = NULL;
	uint32_t rprcnt;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t old_pw_key = {
		.data = old_pw_hash,
		.size = sizeof(old_pw_hash),
	};
	int rc, res;
	NTSTATUS status;

	if (strlen(user) >= sizeof(fstring)-1) {
		DBG_ERR("user name %s is too long.\n", user);
		return NT_STATUS_NAME_TOO_LONG;
	}

	SSVAL(p,0,214); /* SamOEMChangePassword command. */
	p += 2;
	strlcpy(p, "zsT", sizeof(param)-PTR_DIFF(p,param));
	p = skip_string(param,sizeof(param),p);
	strlcpy(p, "B516B16", sizeof(param)-PTR_DIFF(p,param));
	p = skip_string(param,sizeof(param),p);
	strlcpy(p,user, sizeof(param)-PTR_DIFF(p,param));
	p = skip_string(param,sizeof(param),p);
	SSVAL(p,0,532);
	p += 2;

	param_len = PTR_DIFF(p,param);

	/*
	 * Get the Lanman hash of the old password, we
	 * use this as the key to make_oem_passwd_hash().
	 */
	E_deshash(old_password, old_pw_hash);

	encode_pw_buffer(data, new_password, STR_ASCII);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("make_oem_passwd_hash\n"));
	dump_data(100, data, 516);
#endif
	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&old_pw_key,
				NULL);
	if (rc < 0) {
		DBG_ERR("gnutls_cipher_init failed: %s\n",
			gnutls_strerror(rc));
		status = gnutls_error_to_ntstatus(
			rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		return status;
	}
	rc = gnutls_cipher_encrypt(cipher_hnd,
			      data,
			      516);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(
			rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		return status;
	}

	/*
	 * Now place the old password hash in the data.
	 */
	E_deshash(new_password, new_pw_hash);

	rc = E_old_pw_hash( new_pw_hash, old_pw_hash, (uchar *)&data[516]);
	if (rc != 0) {
		DBG_ERR("E_old_pw_hash failed: %s\n", gnutls_strerror(rc));
		status = gnutls_error_to_ntstatus(
			rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		return status;
	}

	status = cli_trans(talloc_tos(),     /* mem_ctx */
			   cli,		     /* cli */
			   SMBtrans,	     /* cmd */
			   "\\PIPE\\LANMAN", /* name */
			   0,		     /* fid */
			   0,		     /* function */
			   0,		     /* flags */
			   NULL,	     /* setup */
			   0,		     /* num_setup */
			   0,		     /* max_setup */
			   (uint8_t *)param, /* param */
			   param_len,	     /* num_param */
			   4,		     /* max_param */
			   data,	     /* data */
			   sizeof(data),     /* num_data */
			   0,		     /* max_data */
			   NULL,	     /* recv_flags2 */
			   NULL,	     /* rsetup */
			   0,		     /* min_rsetup */
			   NULL,	     /* num_rsetup */
			   &rparam,	     /* rparam */
			   2,		     /* min_rparam */
			   &rprcnt,	     /* num_rparam */
			   NULL,	     /* rdata */
			   0,		     /* min_rdata */
			   NULL);	     /* num_rdata */
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	res = PULL_LE_U16(rparam, 0);

	status = werror_to_ntstatus(W_ERROR(res));

	TALLOC_FREE(rparam);

	return status;
}

static void prep_basic_information_buf(
	uint8_t buf[40],
	struct timespec create_time,
	struct timespec access_time,
	struct timespec write_time,
	struct timespec change_time,
	uint32_t attr)
{
	char *p = (char *)buf;
	/*
	 * Add the create, last access, modification, and status change times
	 */
	put_long_date_full_timespec(
		TIMESTAMP_SET_NT_OR_BETTER, p, &create_time);
	p += 8;

	put_long_date_full_timespec(
		TIMESTAMP_SET_NT_OR_BETTER, p, &access_time);
	p += 8;

	put_long_date_full_timespec(
		TIMESTAMP_SET_NT_OR_BETTER, p, &write_time);
	p += 8;

	put_long_date_full_timespec(
		TIMESTAMP_SET_NT_OR_BETTER, p, &change_time);
	p += 8;

	if (attr == (uint32_t)-1 || attr == FILE_ATTRIBUTE_NORMAL) {
		/* No change. */
		attr = 0;
	} else if (attr == 0) {
		/* Clear all existing attributes. */
		attr = FILE_ATTRIBUTE_NORMAL;
	}

	/* Add attributes */
	SIVAL(p, 0, attr);

	p += 4;

	/* Add padding */
	SIVAL(p, 0, 0);
	p += 4;

	SMB_ASSERT(PTR_DIFF(p, buf) == 40);
}

NTSTATUS cli_setpathinfo_ext(struct cli_state *cli, const char *fname,
			     struct timespec create_time,
			     struct timespec access_time,
			     struct timespec write_time,
			     struct timespec change_time,
			     uint32_t attr)
{
	uint8_t buf[40];

	prep_basic_information_buf(
		buf,
		create_time,
		access_time,
		write_time,
		change_time,
		attr);

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		DATA_BLOB in_data = data_blob_const(buf, sizeof(buf));
		/*
		 * Split out SMB2 here as we need to select
		 * the correct info type and level.
		 */
		return cli_smb2_setpathinfo(cli,
					    fname,
					    SMB2_0_INFO_FILE,
					    FSCC_FILE_BASIC_INFORMATION,
					    &in_data);
	}

	return cli_setpathinfo(
		cli, SMB_FILE_BASIC_INFORMATION, fname, buf, sizeof(buf));
}

struct cli_setfileinfo_ext_state {
	uint8_t data[40];
	DATA_BLOB in_data;
};

static void cli_setfileinfo_ext_done(struct tevent_req *subreq);
static void cli_setfileinfo_ext_done2(struct tevent_req *subreq);

struct tevent_req *cli_setfileinfo_ext_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	struct timespec create_time,
	struct timespec access_time,
	struct timespec write_time,
	struct timespec change_time,
	uint32_t attr)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_setfileinfo_ext_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_setfileinfo_ext_state);
	if (req == NULL) {
		return NULL;
	}
	prep_basic_information_buf(
		state->data,
		create_time,
		access_time,
		write_time,
		change_time,
		attr);

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->in_data = (DATA_BLOB) {
			.data = state->data, .length = sizeof(state->data),
		};

		subreq = cli_smb2_set_info_fnum_send(
			state,
			ev,
			cli,
			fnum,
			SMB2_0_INFO_FILE,
			FSCC_FILE_BASIC_INFORMATION,
			&state->in_data,
			0); /* in_additional_info */
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, cli_setfileinfo_ext_done2, req);
		return req;
	}

	subreq = cli_setfileinfo_send(
		state,
		ev,
		cli,
		fnum,
		SMB_FILE_BASIC_INFORMATION,
		state->data,
		sizeof(state->data));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_setfileinfo_ext_done, req);
	return req;
}

static void cli_setfileinfo_ext_done(struct tevent_req *subreq)
{
	NTSTATUS status = cli_setfileinfo_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

static void cli_setfileinfo_ext_done2(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_set_info_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_setfileinfo_ext_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_setfileinfo_ext(
	struct cli_state *cli,
	uint16_t fnum,
	struct timespec create_time,
	struct timespec access_time,
	struct timespec write_time,
	struct timespec change_time,
	uint32_t attr)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	frame = talloc_stackframe();

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_setfileinfo_ext_send(
		ev,
		ev,
		cli,
		fnum,
		create_time,
		access_time,
		write_time,
		change_time,
		attr);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_setfileinfo_ext_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Send a qpathinfo call with the SMB_QUERY_FILE_ALL_INFO info level.
****************************************************************************/

struct cli_qpathinfo2_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *fname;
	struct timespec create_time;
	struct timespec access_time;
	struct timespec write_time;
	struct timespec change_time;
	off_t size;
	uint32_t attr;
	SMB_INO_T ino;
	mode_t mode;
};

static void cli_qpathinfo2_done2(struct tevent_req *subreq);
static void cli_qpathinfo2_done(struct tevent_req *subreq);
static void cli_qpathinfo2_got_reparse(struct tevent_req *subreq);

struct tevent_req *cli_qpathinfo2_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli,
				       const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_qpathinfo2_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_qpathinfo2_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fname = fname;

	state->mode = S_IFREG;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_qpathinfo_send(state,
						 ev,
						 cli,
						 fname,
						 FSCC_FILE_ALL_INFORMATION,
						 0x60,
						 UINT16_MAX);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_qpathinfo2_done2, req);
		return req;
	}
	subreq = cli_qpathinfo_send(state, ev, cli, fname,
				    SMB_QUERY_FILE_ALL_INFO,
				    68, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_qpathinfo2_done, req);
	return req;
}

static void cli_qpathinfo2_done2(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_qpathinfo2_state *state =
		tevent_req_data(req, struct cli_qpathinfo2_state);
	uint8_t *rdata = NULL;
	uint32_t num_rdata;
	NTSTATUS status;

	status = cli_smb2_qpathinfo_recv(subreq, state, &rdata, &num_rdata);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->create_time = interpret_long_date(BVAL(rdata, 0x0));
	state->access_time = interpret_long_date(BVAL(rdata, 0x8));
	state->write_time = interpret_long_date(BVAL(rdata, 0x10));
	state->change_time = interpret_long_date(BVAL(rdata, 0x18));
	state->attr = PULL_LE_U32(rdata, 0x20);
	state->size = PULL_LE_U64(rdata, 0x30);
	state->ino = PULL_LE_U64(rdata, 0x40);

	if (state->attr & FILE_ATTRIBUTE_REPARSE_POINT) {
		subreq = cli_get_reparse_data_send(state,
						   state->ev,
						   state->cli,
						   state->fname);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					cli_qpathinfo2_got_reparse,
					req);
		return;
	}

	tevent_req_done(req);
}

static void cli_qpathinfo2_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_qpathinfo2_state *state = tevent_req_data(
		req, struct cli_qpathinfo2_state);
	uint8_t *data = NULL;
	uint32_t num_data;
	NTSTATUS status;

	status = cli_qpathinfo_recv(subreq, state, &data, &num_data);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->create_time = interpret_long_date(BVAL(data, 0));
	state->access_time = interpret_long_date(BVAL(data, 8));
	state->write_time = interpret_long_date(BVAL(data, 16));
	state->change_time = interpret_long_date(BVAL(data, 24));
	state->attr = PULL_LE_U32(data, 32);
	state->size = PULL_LE_U64(data, 48);

	/*
	 * SMB1 qpathinfo2 uses SMB_QUERY_FILE_ALL_INFO which doesn't
	 * return an inode number (fileid).  We can't change this to
	 * one of the FILE_ID info levels as only Win2003 and above
	 * support these [MS-SMB: 2.2.2.3.1] and the SMB1 code needs
	 * to support older servers.
	 */
	state->ino = 0;

	TALLOC_FREE(data);

	if (state->attr & FILE_ATTRIBUTE_REPARSE_POINT) {
		subreq = cli_get_reparse_data_send(state,
						   state->ev,
						   state->cli,
						   state->fname);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					cli_qpathinfo2_got_reparse,
					req);
		return;
	}

	tevent_req_done(req);
}

static void cli_qpathinfo2_got_reparse(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_qpathinfo2_state *state =
		tevent_req_data(req, struct cli_qpathinfo2_state);
	uint8_t *data = NULL;
	uint32_t num_data;
	struct reparse_data_buffer reparse = {
		.tag = 0,
	};
	NTSTATUS status;

	status = cli_get_reparse_data_recv(subreq, state, &data, &num_data);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = reparse_data_buffer_parse(state, &reparse, data, num_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Ignoring unknown reparse data\n");
		goto done;
	}

	switch (reparse.tag) {
	case IO_REPARSE_TAG_SYMLINK:
		state->mode = S_IFLNK;
		break;
	case IO_REPARSE_TAG_NFS:
		switch (reparse.parsed.nfs.type) {
		case NFS_SPECFILE_LNK:
			state->mode = S_IFLNK;
			break;
		case NFS_SPECFILE_CHR:
			state->mode = S_IFCHR;
			break;
		case NFS_SPECFILE_BLK:
			state->mode = S_IFBLK;
			break;
		case NFS_SPECFILE_FIFO:
			state->mode = S_IFIFO;
			break;
		case NFS_SPECFILE_SOCK:
			state->mode = S_IFSOCK;
			break;
		}
		break;
	}
done:
	tevent_req_done(req);
}

NTSTATUS cli_qpathinfo2_recv(struct tevent_req *req,
			     struct timespec *create_time,
			     struct timespec *access_time,
			     struct timespec *write_time,
			     struct timespec *change_time,
			     off_t *size,
			     uint32_t *pattr,
			     SMB_INO_T *ino,
			     mode_t *mode)
{
	struct cli_qpathinfo2_state *state = tevent_req_data(
		req, struct cli_qpathinfo2_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (create_time) {
		*create_time = state->create_time;
	}
	if (access_time) {
		*access_time = state->access_time;
	}
	if (write_time) {
		*write_time = state->write_time;
	}
	if (change_time) {
		*change_time = state->change_time;
	}
	if (pattr) {
		*pattr = state->attr;
	}
	if (size) {
		*size = state->size;
	}
	if (ino) {
		*ino = state->ino;
	}
	if (mode != NULL) {
		*mode = state->mode;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_qpathinfo2(struct cli_state *cli,
			const char *fname,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size,
			uint32_t *pattr,
			SMB_INO_T *ino,
			mode_t *mode)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_qpathinfo2_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_qpathinfo2_recv(req,
				     create_time,
				     access_time,
				     write_time,
				     change_time,
				     size,
				     pattr,
				     ino,
				     mode);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Get the stream info
****************************************************************************/

struct cli_qpathinfo_streams_state {
	uint32_t num_data;
	uint8_t *data;
};

static void cli_qpathinfo_streams_done(struct tevent_req *subreq);
static void cli_qpathinfo_streams_done2(struct tevent_req *subreq);

struct tevent_req *cli_qpathinfo_streams_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct cli_state *cli,
					      const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_qpathinfo_streams_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_qpathinfo_streams_state);
	if (req == NULL) {
		return NULL;
	}
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_qpathinfo_send(state,
						 ev,
						 cli,
						 fname,
						 FSCC_FILE_STREAM_INFORMATION,
						 0,
						 CLI_BUFFER_SIZE);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					cli_qpathinfo_streams_done2,
					req);
		return req;
	}
	subreq = cli_qpathinfo_send(state, ev, cli, fname,
				    SMB_FILE_STREAM_INFORMATION,
				    0, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_qpathinfo_streams_done, req);
	return req;
}

static void cli_qpathinfo_streams_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_qpathinfo_streams_state *state = tevent_req_data(
		req, struct cli_qpathinfo_streams_state);
	NTSTATUS status;

	status = cli_qpathinfo_recv(subreq, state, &state->data,
				    &state->num_data);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

static void cli_qpathinfo_streams_done2(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_qpathinfo_streams_state *state =
		tevent_req_data(req, struct cli_qpathinfo_streams_state);
	NTSTATUS status;

	status = cli_smb2_qpathinfo_recv(subreq,
					 state,
					 &state->data,
					 &state->num_data);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_qpathinfo_streams_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    unsigned int *pnum_streams,
				    struct stream_struct **pstreams)
{
	struct cli_qpathinfo_streams_state *state = tevent_req_data(
                req, struct cli_qpathinfo_streams_state);
        NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (!parse_streams_blob(mem_ctx, state->data, state->num_data,
				pnum_streams, pstreams)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_qpathinfo_streams(struct cli_state *cli, const char *fname,
			       TALLOC_CTX *mem_ctx,
			       unsigned int *pnum_streams,
			       struct stream_struct **pstreams)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_qpathinfo_streams_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_qpathinfo_streams_recv(req, mem_ctx, pnum_streams,
					    pstreams);
 fail:
	TALLOC_FREE(frame);
	return status;
}

bool parse_streams_blob(TALLOC_CTX *mem_ctx, const uint8_t *rdata,
			       size_t data_len,
			       unsigned int *pnum_streams,
			       struct stream_struct **pstreams)
{
	unsigned int num_streams;
	struct stream_struct *streams;
	unsigned int ofs;

	num_streams = 0;
	streams = NULL;
	ofs = 0;

	while ((data_len > ofs) && (data_len - ofs >= 24)) {
		uint32_t nlen, len;
		size_t size;
		void *vstr;
		struct stream_struct *tmp;
		uint8_t *tmp_buf;

		tmp = talloc_realloc(mem_ctx, streams,
					   struct stream_struct,
					   num_streams+1);

		if (tmp == NULL) {
			goto fail;
		}
		streams = tmp;

		nlen                      = IVAL(rdata, ofs + 0x04);

		streams[num_streams].size = IVAL_TO_SMB_OFF_T(
			rdata, ofs + 0x08);
		streams[num_streams].alloc_size = IVAL_TO_SMB_OFF_T(
			rdata, ofs + 0x10);

		if (nlen > data_len - (ofs + 24)) {
			goto fail;
		}

		/*
		 * We need to null-terminate src, how do I do this with
		 * convert_string_talloc??
		 */

		tmp_buf = talloc_array(streams, uint8_t, nlen+2);
		if (tmp_buf == NULL) {
			goto fail;
		}

		memcpy(tmp_buf, rdata+ofs+24, nlen);
		tmp_buf[nlen] = 0;
		tmp_buf[nlen+1] = 0;

		if (!convert_string_talloc(streams, CH_UTF16, CH_UNIX, tmp_buf,
					   nlen+2, &vstr, &size))
		{
			TALLOC_FREE(tmp_buf);
			goto fail;
		}

		TALLOC_FREE(tmp_buf);
		streams[num_streams].name = (char *)vstr;
		num_streams++;

		len = IVAL(rdata, ofs);
		if (len > data_len - ofs) {
			goto fail;
		}
		if (len == 0) break;
		ofs += len;
	}

	*pnum_streams = num_streams;
	*pstreams = streams;
	return true;

 fail:
	TALLOC_FREE(streams);
	return false;
}

/****************************************************************************
 Send a qfileinfo QUERY_FILE_NAME_INFO call.
****************************************************************************/

struct cli_qfileinfo_basic_state {
	uint32_t attr;
	off_t size;
	struct timespec create_time;
	struct timespec access_time;
	struct timespec write_time;
	struct timespec change_time;
	SMB_INO_T ino;
};

static void cli_qfileinfo_basic_done(struct tevent_req *subreq);
static void cli_qfileinfo_basic_doneE(struct tevent_req *subreq);

struct tevent_req *cli_qfileinfo_basic_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_qfileinfo_basic_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_qfileinfo_basic_state);
	if (req == NULL) {
		return NULL;
	}

	if ((smbXcli_conn_protocol(cli->conn) < PROTOCOL_LANMAN2) ||
	    cli->win95) {
		/*
		 * According to
		 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/3d9d8f3e-dc70-410d-a3fc-6f4a881e8cab
		 * SMB_COM_TRANSACTION2 used in cli_qfileinfo_send()
		 * further down was introduced with the LAN Manager
		 * 1.2 dialect, which we encode as PROTOCOL_LANMAN2.
		 *
		 * The "win95" check was introduced with commit
		 * 27e5850fd3e1c8 in 1998. Hard to check these days,
		 * but leave it in.
		 *
		 * Use a lowerlevel fallback in both cases.
		 */

		subreq = cli_getattrE_send(state, ev, cli, fnum);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, cli_qfileinfo_basic_doneE, req);
		return req;
	}

	subreq = cli_qfileinfo_send(state,
				    ev,
				    cli,
				    fnum,
				    FSCC_FILE_ALL_INFORMATION, /* level */
				    68,			       /* min_rdata */
				    CLI_BUFFER_SIZE);	       /* max_rdata */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_qfileinfo_basic_done, req);
	return req;
}

static void cli_qfileinfo_basic_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_qfileinfo_basic_state *state = tevent_req_data(
		req, struct cli_qfileinfo_basic_state);
	uint8_t *rdata;
	uint32_t num_rdata;
	NTSTATUS status;

	status = cli_qfileinfo_recv(
		subreq, state, NULL, &rdata, &num_rdata);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->create_time = interpret_long_date(BVAL(rdata, 0));
	state->access_time = interpret_long_date(BVAL(rdata, 8));
	state->write_time = interpret_long_date(BVAL(rdata, 16));
	state->change_time = interpret_long_date(BVAL(rdata, 24));
	state->attr = PULL_LE_U32(rdata, 32);
	state->size = PULL_LE_U64(rdata,48);
	state->ino = PULL_LE_U32(rdata, 64);
	TALLOC_FREE(rdata);

	tevent_req_done(req);
}

static void cli_qfileinfo_basic_doneE(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_qfileinfo_basic_state *state = tevent_req_data(
		req, struct cli_qfileinfo_basic_state);
	NTSTATUS status;

	status = cli_getattrE_recv(
		subreq,
		&state->attr,
		&state->size,
		&state->change_time.tv_sec,
		&state->access_time.tv_sec,
		&state->write_time.tv_sec);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_qfileinfo_basic_recv(
	struct tevent_req *req,
	uint32_t *attr,
	off_t *size,
	struct timespec *create_time,
	struct timespec *access_time,
	struct timespec *write_time,
	struct timespec *change_time,
	SMB_INO_T *ino)
{
	struct cli_qfileinfo_basic_state *state = tevent_req_data(
		req, struct cli_qfileinfo_basic_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (create_time != NULL) {
		*create_time = state->create_time;
	}
	if (access_time != NULL) {
		*access_time = state->access_time;
	}
	if (write_time != NULL) {
		*write_time = state->write_time;
	}
	if (change_time != NULL) {
		*change_time = state->change_time;
	}
	if (attr != NULL) {
		*attr = state->attr;
	}
	if (size != NULL) {
                *size = state->size;
	}
	if (ino) {
		*ino = state->ino;
	}

	return NT_STATUS_OK;
}
/****************************************************************************
 Send a qfileinfo call.
****************************************************************************/

NTSTATUS cli_qfileinfo_basic(
	struct cli_state *cli,
	uint16_t fnum,
	uint32_t *attr,
	off_t *size,
	struct timespec *create_time,
	struct timespec *access_time,
	struct timespec *write_time,
	struct timespec *change_time,
	SMB_INO_T *ino)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_qfileinfo_basic_send(frame, ev, cli, fnum);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_qfileinfo_basic_recv(
		req,
		attr,
		size,
		create_time,
		access_time,
		write_time,
		change_time,
		ino);
fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Send a qpathinfo BASIC_INFO call.
****************************************************************************/

struct cli_qpathinfo_basic_state {
	uint32_t num_data;
	uint8_t *data;
};

static void cli_qpathinfo_basic_done(struct tevent_req *subreq);

struct tevent_req *cli_qpathinfo_basic_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_qpathinfo_basic_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_qpathinfo_basic_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = cli_qpathinfo_send(state, ev, cli, fname,
				    SMB_QUERY_FILE_BASIC_INFO,
				    36, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_qpathinfo_basic_done, req);
	return req;
}

static void cli_qpathinfo_basic_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_qpathinfo_basic_state *state = tevent_req_data(
		req, struct cli_qpathinfo_basic_state);
	NTSTATUS status;

	status = cli_qpathinfo_recv(subreq, state, &state->data,
				    &state->num_data);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_qpathinfo_basic_recv(struct tevent_req *req,
				  SMB_STRUCT_STAT *sbuf, uint32_t *attributes)
{
	struct cli_qpathinfo_basic_state *state = tevent_req_data(
		req, struct cli_qpathinfo_basic_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	sbuf->st_ex_btime = interpret_long_date(BVAL(state->data, 0));
	sbuf->st_ex_atime = interpret_long_date(BVAL(state->data, 8));
	sbuf->st_ex_mtime = interpret_long_date(BVAL(state->data, 16));
	sbuf->st_ex_ctime = interpret_long_date(BVAL(state->data, 24));
	*attributes = IVAL(state->data, 32);
	return NT_STATUS_OK;
}

NTSTATUS cli_qpathinfo_basic(struct cli_state *cli, const char *name,
			     SMB_STRUCT_STAT *sbuf, uint32_t *attributes)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_qpathinfo_basic(cli,
						name,
						sbuf,
						attributes);
	}

	frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_qpathinfo_basic_send(frame, ev, cli, name);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_qpathinfo_basic_recv(req, sbuf, attributes);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Send a qpathinfo SMB_QUERY_FILE_ALT_NAME_INFO call.
****************************************************************************/

NTSTATUS cli_qpathinfo_alt_name(struct cli_state *cli, const char *fname, fstring alt_name)
{
	uint8_t *rdata;
	uint32_t num_rdata;
	unsigned int len;
	char *converted = NULL;
	size_t converted_size = 0;
	NTSTATUS status;

	status = cli_qpathinfo(talloc_tos(), cli, fname,
			       SMB_QUERY_FILE_ALT_NAME_INFO,
			       4, CLI_BUFFER_SIZE, &rdata, &num_rdata);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	len = IVAL(rdata, 0);

	if (len > num_rdata - 4) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/* The returned data is a pushed string, not raw data. */
	if (!convert_string_talloc(talloc_tos(),
				   smbXcli_conn_use_unicode(cli->conn) ? CH_UTF16LE : CH_DOS,
				   CH_UNIX,
				   rdata + 4,
				   len,
				   &converted,
				   &converted_size)) {
		return NT_STATUS_NO_MEMORY;
	}
	fstrcpy(alt_name, converted);

	TALLOC_FREE(converted);
	TALLOC_FREE(rdata);

	return NT_STATUS_OK;
}

/****************************************************************************
 Send a qpathinfo SMB_QUERY_FILE_STANDARD_INFO call.
****************************************************************************/

static NTSTATUS cli_qpathinfo_standard(struct cli_state *cli,
				       const char *fname,
				       uint64_t *allocated,
				       uint64_t *size,
				       uint32_t *nlinks,
				       bool *is_del_pending,
				       bool *is_dir)
{
	uint8_t *rdata;
	uint32_t num_rdata;
	NTSTATUS status;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	status = cli_qpathinfo(talloc_tos(), cli, fname,
			       SMB_QUERY_FILE_STANDARD_INFO,
			       24, CLI_BUFFER_SIZE, &rdata, &num_rdata);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (allocated) {
		*allocated = BVAL(rdata, 0);
	}

	if (size) {
		*size = BVAL(rdata, 8);
	}

	if (nlinks) {
		*nlinks = IVAL(rdata, 16);
	}

	if (is_del_pending) {
		*is_del_pending = CVAL(rdata, 20);
	}

	if (is_dir) {
		*is_dir = CVAL(rdata, 20);
	}

	TALLOC_FREE(rdata);

	return NT_STATUS_OK;
}


/* like cli_qpathinfo2 but do not use SMB_QUERY_FILE_ALL_INFO with smb1 */
NTSTATUS cli_qpathinfo3(struct cli_state *cli, const char *fname,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size, uint32_t *pattr,
			SMB_INO_T *ino)
{
	NTSTATUS status = NT_STATUS_OK;
	SMB_STRUCT_STAT st = { 0 };
	uint32_t attr = 0;
	uint64_t pos;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		/*
		 * NB. cli_qpathinfo2() checks pattr is valid before
		 * storing a value into it, so we don't need to use
		 * an intermediate attr variable as below but can
		 * pass pattr directly.
		 */
		return cli_qpathinfo2(cli,
				      fname,
				      create_time,
				      access_time,
				      write_time,
				      change_time,
				      size,
				      pattr,
				      ino,
				      NULL);
	}

	if (create_time || access_time || write_time || change_time || pattr) {
		/*
		 * cli_qpathinfo_basic() always indirects the passed
		 * in pointers so we use intermediate variables to
		 * collect all of them before assigning any requested
		 * below.
		 */
		status = cli_qpathinfo_basic(cli, fname, &st, &attr);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (size) {
		status = cli_qpathinfo_standard(cli, fname,
						NULL, &pos, NULL, NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		*size = pos;
	}

	if (create_time) {
		*create_time = st.st_ex_btime;
	}
	if (access_time) {
		*access_time = st.st_ex_atime;
	}
	if (write_time) {
		*write_time = st.st_ex_mtime;
	}
	if (change_time) {
		*change_time = st.st_ex_ctime;
	}
	if (pattr) {
		*pattr = attr;
	}
	if (ino) {
		*ino = 0;
	}

	return NT_STATUS_OK;
}
